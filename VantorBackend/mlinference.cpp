#include "mlinference.h"
#include "VantorBackend.h"
#include <xgboost/c_api.h>
#include <algorithm>

MLInference::~MLInference() {
    for (void* booster : boosters) {
        XGBoosterFree((BoosterHandle)booster);
    }
}

bool MLInference::load_models(const std::vector<std::string>& model_paths) {
    boosters.clear();
    for (const auto& path : model_paths) {
        BoosterHandle booster = nullptr;
        if (XGBoosterCreate(nullptr, 0, &booster) != 0) {
            log_event_json({ {"type","ml_error"},{"msg","BoosterCreate failed"} });
            return false;
        }
        if (XGBoosterLoadModel(booster, path.c_str()) != 0) {
            log_event_json({ {"type","ml_error"},{"msg","LoadModel failed"},{"path",path} });
            XGBoosterFree(booster);
            return false;
        }
        XGBoosterSetParam(booster, "nthread", "2");
        boosters.push_back((void*)booster);
    }
    log_event_json({ {"type","ml_init"}, {"models_loaded",(int)boosters.size()} });
    return !boosters.empty();
}

double MLInference::predict(const std::vector<float>& features) const {
    if (boosters.empty() || features.empty())
        return 0.0;

    double sum = 0.0;
    for (size_t i = 0; i < boosters.size(); ++i) {
        void* booster = boosters[i];
        DMatrixHandle mat;
        // Corrected bst_ulong cast 
        XGDMatrixCreateFromMat(features.data(), 1, (bst_ulong)features.size(), -1.0f, &mat);

        bst_ulong out_len = 0;
        const float* out = nullptr;
        // Corrected XGBoosterPredict signature with 6 arguments 
        XGBoosterPredict((BoosterHandle)booster, mat, 0, 0, 0, &out_len, &out);

        if (out_len > 0) {
            float score = std::clamp(out[0], 0.0f, 1.0f);
            sum += score;

            // NEW LOGGING LOGIC
            // Logs individual model prediction to logs.jsonl
            log_event_json({
                {"type", "ml_score_prediction"},
                {"model_index", (int)i},
                {"score", (double)score}
                });
        }

        XGDMatrixFree(mat);
    }

    double final_avg = sum / boosters.size();

    return final_avg;
}