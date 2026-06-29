#include "messaging/kafka_consumer.hpp"
#include "alert/broadcaster.hpp"

#include "alerts.grpc.pb.h"   // generated from proto/alerts.proto at build time

#include <grpcpp/grpcpp.h>
#include <nlohmann/json.hpp>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <thread>

using namespace ids;

static std::atomic<bool> g_stop{false};
static void on_signal(int) { g_stop = true; }

// One Subscribe() call runs per connected client on its own gRPC thread: register
// a queue with the broadcaster, then drain it to the client's stream until it
// disconnects.
class AlertServiceImpl final : public AlertStream::Service {
public:
    explicit AlertServiceImpl(AlertBroadcaster& b) : b_{b} {}

    grpc::Status Subscribe(grpc::ServerContext* ctx,
                           const SubscribeRequest* req,
                           grpc::ServerWriter<FlowAlert>* writer) override {
        const float min_prob{req->min_prob()};
        auto queue = b_.subscribe();
        printf("client connected (min_prob=%.2f); %zu now subscribed\n",
               min_prob, b_.client_count());

        while (!ctx->IsCancelled()) {
            std::string msg;
            if (!queue->pop(msg, std::chrono::milliseconds(200)))
                continue;                   // timeout: re-check IsCancelled

            auto j = nlohmann::json::parse(msg, nullptr, false);
            if (j.is_discarded()) continue;
            const float p{j.value("attack_prob", 0.0f)};
            if (p < min_prob) continue;     // honor the client's filter

            FlowAlert a;
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
    const char* be{std::getenv("KAFKA_BROKERS")};
    const std::string brokers{be ? be : "localhost:9092"};
    const char* ga{std::getenv("GRPC_ADDR")};
    const std::string addr{ga ? ga : "0.0.0.0:50051"};

    std::signal(SIGINT,  on_signal);
    std::signal(SIGTERM, on_signal);

    AlertBroadcaster broadcaster;

    // Kafka consumer thread: scored-flows -> broadcast novel (deduped) alerts.
    std::atomic<bool> consuming{true};
    std::thread consumer_thread([&] {
        KafkaConsumer consumer{brokers, "alert-gateway", "scored-flows"};
        while (consuming) {
            auto msg = consumer.poll(200);
            if (!msg) continue;
            auto j = nlohmann::json::parse(*msg, nullptr, false);
            if (j.is_discarded()) continue;
            if (j.value("alert", false)) broadcaster.publish(*msg);
        }
        consumer.close();
    });

    AlertServiceImpl service{broadcaster};
    grpc::ServerBuilder builder;
    builder.AddListeningPort(addr, grpc::InsecureServerCredentials());
    builder.RegisterService(&service);
    std::unique_ptr<grpc::Server> server{builder.BuildAndStart()};
    printf("alert_gateway: gRPC on %s, consuming scored-flows from %s\n",
           addr.c_str(), brokers.c_str());

    // Calling Shutdown() from a signal handler is unsafe, so a small thread turns
    // the flag into a clean Shutdown() on the main thread's behalf.
    std::thread watcher([&] {
        while (!g_stop) std::this_thread::sleep_for(std::chrono::milliseconds(200));
        consuming = false;
        server->Shutdown();
    });

    server->Wait();
    watcher.join();
    consumer_thread.join();
    printf("\nalert_gateway stopped\n");
    return 0;
}
