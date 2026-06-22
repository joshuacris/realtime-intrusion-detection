#include "kafka_consumer.h"
#include "alert_broadcaster.h"

#include "alerts.grpc.pb.h"   // generated from proto/alerts.proto at build time

#include <grpcpp/grpcpp.h>
#include <nlohmann/json.hpp>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <thread>

static std::atomic<bool> g_stop{false};
static void on_signal(int) { g_stop = true; }

// ---- The gRPC service implementation ----
// One Subscribe() call runs PER connected client, on its own gRPC thread. It
// registers a queue with the broadcaster, then loops: drain the queue, write
// each alert to the client's stream, until the client disconnects.
class AlertServiceImpl final : public ids::AlertStream::Service {
public:
    explicit AlertServiceImpl(AlertBroadcaster& b) : b_(b) {}

    grpc::Status Subscribe(grpc::ServerContext* ctx,
                           const ids::SubscribeRequest* req,
                           grpc::ServerWriter<ids::FlowAlert>* writer) override {
        const float min_prob = req->min_prob();
        auto queue = b_.subscribe();
        printf("client connected (min_prob=%.2f); %zu now subscribed\n",
               min_prob, b_.client_count());

        while (!ctx->IsCancelled()) {       // IsCancelled() == client went away
            std::string msg;
            if (!queue->pop(msg, std::chrono::milliseconds(200)))
                continue;                   // timeout: loop to re-check IsCancelled

            auto j = nlohmann::json::parse(msg, nullptr, false);
            if (j.is_discarded()) continue;
            const float p = j.value("attack_prob", 0.0f);
            if (p < min_prob) continue;     // honor the client's filter

            ids::FlowAlert a;
            a.set_srcip(j.value("srcip", std::string("")));
            a.set_sport(j.value("sport", 0));
            a.set_dstip(j.value("dstip", std::string("")));
            a.set_dsport(j.value("dsport", 0));
            a.set_proto(j.value("proto", std::string("")));
            a.set_attack_prob(p);
            a.set_latency_us(j.value("latency_us", static_cast<int64_t>(0)));

            if (!writer->Write(a)) break;   // Write fails -> client disconnected
        }

        b_.unsubscribe(queue);
        printf("client disconnected; %zu still subscribed\n", b_.client_count());
        return grpc::Status::OK;
    }

private:
    AlertBroadcaster& b_;
};

int main() {
    const char* be = std::getenv("KAFKA_BROKERS");
    const std::string brokers = be ? be : "localhost:9092";
    const char* ga = std::getenv("GRPC_ADDR");
    const std::string addr = ga ? ga : "0.0.0.0:50051";

    std::signal(SIGINT,  on_signal);
    std::signal(SIGTERM, on_signal);

    AlertBroadcaster broadcaster;

    // ---- Kafka consumer thread: scored-flows -> broadcast novel alerts ----
    std::atomic<bool> consuming{true};
    std::thread consumer_thread([&] {
        KafkaConsumer consumer(brokers, "alert-gateway", "scored-flows");
        while (consuming) {
            auto msg = consumer.poll(200);
            if (!msg) continue;
            auto j = nlohmann::json::parse(*msg, nullptr, false);
            if (j.is_discarded()) continue;
            if (j.value("alert", false))           // only deduped novel attacks
                broadcaster.publish(*msg);
        }
        consumer.close();
    });

    // ---- Build and start the gRPC server ----
    AlertServiceImpl service(broadcaster);
    grpc::ServerBuilder builder;
    builder.AddListeningPort(addr, grpc::InsecureServerCredentials());
    builder.RegisterService(&service);
    std::unique_ptr<grpc::Server> server = builder.BuildAndStart();
    printf("alert_gateway: gRPC on %s, consuming scored-flows from %s\n",
           addr.c_str(), brokers.c_str());

    // ---- Shutdown watcher: turn the signal flag into a clean Shutdown() ----
    // (Calling server->Shutdown() directly from a signal handler is unsafe, so a
    //  small thread polls the flag and shuts down on the main thread's behalf.)
    std::thread watcher([&] {
        while (!g_stop) std::this_thread::sleep_for(std::chrono::milliseconds(200));
        consuming = false;
        server->Shutdown();
    });

    server->Wait();          // blocks until Shutdown() is called
    watcher.join();
    consumer_thread.join();
    printf("\nalert_gateway stopped\n");
    return 0;
}