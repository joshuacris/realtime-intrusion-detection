#pragma once

#include <onnxruntime_cxx_api.h>
#include <string>
#include <vector>
#include <cstddef>

namespace ids {

// Loads an ONNX model and scores batches of feature vectors. Input "input"
// [N,58] -> output "probabilities" [N,2]; column 1 is the attack probability.
class OnnxModel {
public:
    static constexpr int FEATURES{58};   // must match feature_schema.hpp

    explicit OnnxModel(const std::string& model_path);

    // Score n feature vectors packed row-major into `flat` (size n*58); returns
    // the attack probability for each row.
    std::vector<float> predict(const std::vector<float>& flat, std::size_t n);

private:
    Ort::Env            env_;
    Ort::SessionOptions opts_;
    Ort::Session        session_{nullptr};   // built in the ctor body
};

}  // namespace ids
