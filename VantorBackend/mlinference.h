#pragma once
#include <vector>
#include <string>

/*
  Thin ML inference wrapper around XGBoost JSON models.
  - Supports multiple models (ensemble)
  - Deterministic
  - Safe failure behavior
*/

class MLInference {
public:
    bool load_models(const std::vector<std::string>& model_paths);
    double predict(const std::vector<float>& features) const;
    bool is_ready() const { return !boosters.empty(); }

    ~MLInference();

private:
    std::vector<void*> boosters; // XGBoost booster handles
};
