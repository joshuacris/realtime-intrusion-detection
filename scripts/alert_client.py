#!/usr/bin/env python3
"""
Test client for the gRPC alert stream (Phase 3.5).

First generate the Python stubs from the proto (once):
  .venv/bin/python -m grpc_tools.protoc -I cpp/proto \
      --python_out=scripts/gen --grpc_python_out=scripts/gen cpp/proto/alerts.proto

Then run:
  .venv/bin/python scripts/alert_client.py [min_prob]
"""
import os
import sys

# The generated stubs live in scripts/gen/.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "gen"))

import grpc
import alerts_pb2
import alerts_pb2_grpc


def main():
    addr = os.environ.get("GRPC_ADDR", "localhost:50051")
    min_prob = float(sys.argv[1]) if len(sys.argv) > 1 else 0.0

    channel = grpc.insecure_channel(addr)
    stub = alerts_pb2_grpc.AlertStreamStub(channel)
    print(f"subscribing to {addr} (min_prob={min_prob}); Ctrl-C to stop")

    try:
        # Server-streaming call: send one request, iterate the response stream.
        for a in stub.Subscribe(alerts_pb2.SubscribeRequest(min_prob=min_prob)):
            print(f"ALERT  {a.srcip}:{a.sport} -> {a.dstip}:{a.dsport}  "
                  f"{a.proto}  prob={a.attack_prob:.3f}  latency={a.latency_us}us")
    except grpc.RpcError as e:
        print(f"stream ended: {e.code()}")
    except KeyboardInterrupt:
        print("\nclient stopped")


if __name__ == "__main__":
    main()