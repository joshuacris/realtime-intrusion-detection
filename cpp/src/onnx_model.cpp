#include "onnx_model.h"
#include <array>

OnnxModel::OnnxModel(const std::string& model_path)
    // env_ must exist before the session; session_ starts empty (see header).
    : env_(ORT_LOGGING_LEVEL_WARNING, "ids-inference") {
    // Configure options, THEN build the session from them. (We must set options
    // before constructing the session, so we move-assign session_ in the body
    // rather than the initializer list.)
    opts_.SetIntraOpNumThreads(1);   // 1 thread/call; we parallelize via Kafka
    opts_.SetGraphOptimizationLevel(GraphOptimizationLevel::ORT_ENABLE_ALL);
    session_ = Ort::Session(env_, model_path.c_str(), opts_);
}

std::vector<float> OnnxModel::predict(const std::vector<float>& flat,
                                      std::size_t n) {
    // Describe the input tensor's shape: n rows x 58 features.
    std::array<int64_t, 2> shape{static_cast<int64_t>(n), FEATURES};

    // Wrap our existing float buffer as a tensor WITHOUT copying (the tensor
    // just points at flat's memory; flat must outlive this call — it does).
    Ort::MemoryInfo mem =
        Ort::MemoryInfo::CreateCpu(OrtArenaAllocator, OrtMemTypeDefault);
    Ort::Value input = Ort::Value::CreateTensor<float>(
        mem, const_cast<float*>(flat.data()), flat.size(),
        shape.data(), shape.size());

    // We know the model's tensor names from the export, so hardcode them.
    const char* in_names[]  = {"input"};
    const char* out_names[] = {"probabilities"};

    // Run the model on the whole batch in one call.
    auto outputs = session_.Run(Ort::RunOptions{nullptr},
                                in_names, &input, 1, out_names, 1);

    // probabilities is [n,2] row-major; attack prob of row i is element 2*i+1.
    const float* p = outputs[0].GetTensorMutableData<float>();
    std::vector<float> attack(n);
    for (std::size_t i = 0; i < n; ++i) attack[i] = p[2 * i + 1];
    return attack;
}