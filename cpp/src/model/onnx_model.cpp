#include "model/onnx_model.hpp"
#include <array>

namespace ids {

OnnxModel::OnnxModel(const std::string& model_path)
    : env_{ORT_LOGGING_LEVEL_WARNING, "ids-inference"} {
    // Options must be set before the session is built, so session_ is
    // move-assigned in the body rather than the initializer list.
    opts_.SetIntraOpNumThreads(1);   // 1 thread/call; parallelism comes from Kafka
    opts_.SetGraphOptimizationLevel(GraphOptimizationLevel::ORT_ENABLE_ALL);
    session_ = Ort::Session(env_, model_path.c_str(), opts_);
}

std::vector<float> OnnxModel::predict(const std::vector<float>& flat,
                                      std::size_t n) {
    std::array<int64_t, 2> shape{static_cast<int64_t>(n), FEATURES};

    // Wrap flat's memory as a tensor without copying (flat must outlive this call).
    Ort::MemoryInfo mem{
        Ort::MemoryInfo::CreateCpu(OrtArenaAllocator, OrtMemTypeDefault)};
    Ort::Value input{Ort::Value::CreateTensor<float>(
        mem, const_cast<float*>(flat.data()), flat.size(),
        shape.data(), shape.size())};

    const char* in_names[]{"input"};
    const char* out_names[]{"probabilities"};

    auto outputs = session_.Run(Ort::RunOptions{nullptr},
                                in_names, &input, 1, out_names, 1);

    // probabilities is [n,2] row-major; attack prob of row i is element 2*i+1.
    const float* p{outputs[0].GetTensorMutableData<float>()};
    std::vector<float> attack(n);
    for (std::size_t i = 0; i < n; ++i) attack[i] = p[2 * i + 1];
    return attack;
}

}  // namespace ids
