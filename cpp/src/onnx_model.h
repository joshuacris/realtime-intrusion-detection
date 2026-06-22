#pragma once

#include <onnxruntime_cxx_api.h>   // the ONNX Runtime C++ API (namespace Ort)
#include <string>
#include <vector>
#include <cstddef>

// ===================================================================
// OnnxModel — loads an ONNX model and scores batches of feature vectors.
//
// Wraps the ONNX Runtime objects (Env/Session) behind one method: predict().
// Our model takes input "input" [N,58] and returns "probabilities" [N,2];
// column 1 is the attack probability.
// ===================================================================
class OnnxModel {
public:
    static constexpr int FEATURES = 58;   // must match feature_schema.h

    explicit OnnxModel(const std::string& model_path);

    // Score n feature vectors packed row-major into `flat` (size n*58).
    // Returns the attack probability for each of the n rows.
    std::vector<float> predict(const std::vector<float>& flat, std::size_t n);

private:
    Ort::Env            env_;
    Ort::SessionOptions opts_;
    Ort::Session        session_{nullptr};   // start empty; built in the ctor body
};