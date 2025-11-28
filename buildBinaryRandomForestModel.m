%% Build Binary Random Forest Model for Bluetooth Mesh IDS
% This script builds a Binary Random Forest model (Attack vs Normal)
% from your training data and saves it in a format that MATLAB can use
%
% Author: AI Assistant
% Date: November 27, 2025

clear all; close all; clc;

%% Configuration
TRAINING_DATA_DIR = 'training_data';
MODELS_DIR = 'models';
USE_ALL_DATA = true; % Using both balanced and unbalanced datasets
VALIDATION_SPLIT = 0.2; % 20% for validation
RANDOM_SEED = 42;

% Model hyperparameters
NUM_TREES = 500;
MIN_LEAF_SIZE = 2;
MAX_NUM_SPLITS = []; % Let MATLAB decide optimal splits

fprintf('Building Binary Random Forest Model for Bluetooth Mesh IDS\n');
fprintf('=========================================================\n');
fprintf('This model classifies traffic as: ATTACK or NORMAL\n\n');

%% Create models directory if it doesn't exist
if ~exist(MODELS_DIR, 'dir')
    mkdir(MODELS_DIR);
end

%% Find and Load Training Data
fprintf('1. Loading training data...\n');

% Get list of available datasets
balanced_pattern = fullfile(TRAINING_DATA_DIR, 'merged_shuffled_feature_dataset1.csv');
balanced_files = dir(balanced_pattern);

files = balanced_files;
fprintf('   Found %d balanced dataset files\n', length(balanced_files));
fprintf('   Using only balanced datasets.\n');

if isempty(files)
    error('No training data files found in %s', TRAINING_DATA_DIR);
end

% Sort files by date
[~, idx] = sort([files.datenum], 'descend');
files = files(idx);

fprintf('   Total: %d dataset files\n', length(files));
fprintf('   Loading and combining all datasets...\n');

% Load and combine all data files
combined_data = table();
total_samples = 0;

for i = 1:length(files)
    file_path = fullfile(files(i).folder, files(i).name);
    fprintf('   Processing file %d/%d: %s\n', i, length(files), files(i).name);
    
    try
        current_data = readtable(file_path);
        
        % Add file source information
        current_data.source_file = repmat({files(i).name}, height(current_data), 1);
        
        % Combine with existing data
        if isempty(combined_data)
            combined_data = current_data;
        else
            % Ensure consistent column names and order
            common_cols = intersect(combined_data.Properties.VariableNames, ...
                                  current_data.Properties.VariableNames, 'stable');
            combined_data = [combined_data(:, common_cols); current_data(:, common_cols)];
        end
        
        fprintf('     ✅ Loaded %d samples\n', height(current_data));
        total_samples = total_samples + height(current_data);
        
    catch ME
        fprintf('     ⚠️  Failed to load %s: %s\n', files(i).name, ME.message);
        continue;
    end
end

if isempty(combined_data)
    error('No data could be loaded from any files');
end

data = combined_data;
fprintf('   ✅ Combined dataset loaded: %d total samples from %d files\n', total_samples, length(files));

%% Data Preprocessing - Convert to Binary Classification
fprintf('\n2. Preprocessing data for binary classification...\n');

% Identify feature columns (attack_type is the label, rest are features)
% Note: Cleaned CSV only has attack_type + features (no other metadata)
label_col = 'attack_type';
feature_cols = setdiff(data.Properties.VariableNames, {label_col, 'source_file'}, 'stable');

% Extract features
X = table2array(data(:, feature_cols));

% Convert multi-class labels to binary (ATTACK vs NORMAL)
original_labels = data.attack_type;
if iscategorical(original_labels)
    original_labels = cellstr(original_labels);
end

% Create binary labels
y_binary = cell(size(original_labels));
for i = 1:length(original_labels)
    if strcmp(original_labels{i}, 'NORMAL')
        y_binary{i} = 'NORMAL';
    else
        y_binary{i} = 'ATTACK';
    end
end

fprintf('   Original class distribution:\n');
unique_original = unique(original_labels);
for i = 1:length(unique_original)
    count = sum(strcmp(original_labels, unique_original{i}));
    percentage = (count / length(original_labels)) * 100;
    fprintf('     %s: %d (%.1f%%)\n', unique_original{i}, count, percentage);
end

fprintf('\n   Binary class distribution:\n');
unique_classes = {'ATTACK', 'NORMAL'};
for i = 1:length(unique_classes)
    count = sum(strcmp(y_binary, unique_classes{i}));
    percentage = (count / length(y_binary)) * 100;
    fprintf('     %s: %d (%.1f%%)\n', unique_classes{i}, count, percentage);
end

% Check for missing values
missing_count = sum(any(isnan(X), 2));
if missing_count > 0
    fprintf('   ⚠️  Found %d samples with missing values, removing them\n', missing_count);
    valid_idx = ~any(isnan(X), 2);
    X = X(valid_idx, :);
    y_binary = y_binary(valid_idx);
end

% Check for infinite values
inf_count = sum(any(isinf(X), 2));
if inf_count > 0
    fprintf('   ⚠️  Found %d samples with infinite values, removing them\n', inf_count);
    valid_idx = ~any(isinf(X), 2);
    X = X(valid_idx, :);
    y_binary = y_binary(valid_idx);
end

fprintf('   ✅ Final dataset: %d samples, %d features\n', size(X, 1), size(X, 2));

% Validate feature ranges
fprintf('\n2.5. Validating feature ranges...\n');
feature_mins = min(X);
feature_maxs = max(X);
out_of_bounds_min = find(feature_mins < -0.1);
out_of_bounds_max = find(feature_maxs > 1.1);

if ~isempty(out_of_bounds_min) || ~isempty(out_of_bounds_max)
    fprintf('   ⚠️  WARNING: Features outside [0,1] range:\n');
    if ~isempty(out_of_bounds_min)
        for idx = out_of_bounds_min
            fprintf('      %s: min=%.4f (below 0)\n', feature_cols{idx}, feature_mins(idx));
        end
    end
    if ~isempty(out_of_bounds_max)
        for idx = out_of_bounds_max
            fprintf('      %s: max=%.4f (above 1)\n', feature_cols{idx}, feature_maxs(idx));
        end
    end
else
    fprintf('   ✅ All features within [0,1] range\n');
end

% Check binary class balance
fprintf('\n2.6. Checking binary class balance...\n');
attack_count = sum(strcmp(y_binary, 'ATTACK'));
normal_count = sum(strcmp(y_binary, 'NORMAL'));
imbalance_ratio = max(attack_count, normal_count) / min(attack_count, normal_count);
fprintf('   Class imbalance ratio: %.1f:1\n', imbalance_ratio);
if imbalance_ratio > 2
    fprintf('   ⚠️  WARNING: Moderate class imbalance detected\n');
else
    fprintf('   ✅ Class distribution is well balanced\n');
end

% Calculate number of features to sample
NUM_FEATURES_SAMPLE = round(sqrt(size(X, 2)));

%% Train-Validation Split
fprintf('\n3. Splitting data for training and validation...\n');

rng(RANDOM_SEED);

% Stratified split for binary classification
n_samples = length(y_binary);
train_idx = [];
val_idx = [];

for i = 1:length(unique_classes)
    class_name = unique_classes{i};
    class_idx = find(strcmp(y_binary, class_name));
    n_class = length(class_idx);
    
    n_val = round(n_class * VALIDATION_SPLIT);
    val_class_idx = class_idx(randperm(n_class, n_val));
    train_class_idx = setdiff(class_idx, val_class_idx);
    
    train_idx = [train_idx; train_class_idx];
    val_idx = [val_idx; val_class_idx];
end

% Create training and validation sets
X_train = X(train_idx, :);
y_train = y_binary(train_idx);
X_val = X(val_idx, :);
y_val = y_binary(val_idx);

fprintf('   Training set: %d samples\n', length(y_train));
fprintf('     - ATTACK: %d\n', sum(strcmp(y_train, 'ATTACK')));
fprintf('     - NORMAL: %d\n', sum(strcmp(y_train, 'NORMAL')));
fprintf('   Validation set: %d samples\n', length(y_val));
fprintf('     - ATTACK: %d\n', sum(strcmp(y_val, 'ATTACK')));
fprintf('     - NORMAL: %d\n', sum(strcmp(y_val, 'NORMAL')));

%% Build Binary Random Forest Model
fprintf('\n4. Training Binary Random Forest model...\n');
fprintf('   Parameters:\n');
fprintf('     - Number of trees: %d\n', NUM_TREES);
fprintf('     - Minimum leaf size: %d\n', MIN_LEAF_SIZE);
fprintf('     - Features per split: %d (sqrt of %d)\n', NUM_FEATURES_SAMPLE, size(X, 2));
fprintf('     - Classes: ATTACK, NORMAL\n');

tic;
try
    fprintf('   Training Random Forest with %d trees...\n', NUM_TREES);
    
    % Temporarily capture and suppress output during training
    evalc_cmd = sprintf(['rf_model = TreeBagger(%d, X_train, y_train, ' ...
        '''Method'', ''classification'', ' ...
        '''MinLeafSize'', %d, ' ...
        '''NumVariablesToSample'', %d, ' ...
        '''OOBPrediction'', ''on'', ' ...
        '''OOBPredictorImportance'', ''on'');'], ...
        NUM_TREES, MIN_LEAF_SIZE, NUM_FEATURES_SAMPLE);
    
    evalc(evalc_cmd);
    
    training_time = toc;
    fprintf('   ✅ Binary model trained successfully in %.2f seconds\n', training_time);
    
    % Display final OOB error
    final_oob_error = oobError(rf_model, 'mode', 'ensemble');
    fprintf('   📊 Final Out-of-Bag Error: %.4f (%.2f%% accuracy)\n', ...
        final_oob_error, (1 - final_oob_error) * 100);
    
catch ME
    error('Failed to train model: %s', ME.message);
end

%% Model Evaluation
fprintf('\n5. Evaluating binary model performance...\n');

% Out-of-bag error
oob_error = oobError(rf_model);
fprintf('   Out-of-bag error: %.4f (%.2f%% accuracy)\n', oob_error, (1-oob_error)*100);

% Validation set predictions
[y_pred, scores] = predict(rf_model, X_val);

% Calculate accuracy
accuracy = sum(strcmp(y_val, y_pred)) / length(y_val);
fprintf('   Validation accuracy: %.2f%%\n', accuracy * 100);

% Confusion matrix
fprintf('\n   Confusion Matrix:\n');
[C, order] = confusionmat(y_val, y_pred);
confusion_table = array2table(C, 'RowNames', order, 'VariableNames', order);
disp(confusion_table);

% Binary classification metrics
fprintf('\n   Binary Classification Metrics:\n');

% Find indices for ATTACK and NORMAL
attack_idx = find(strcmp(order, 'ATTACK'));
normal_idx = find(strcmp(order, 'NORMAL'));

% True Positives, False Positives, True Negatives, False Negatives
TP = C(attack_idx, attack_idx);  % Correctly predicted attacks
FP = C(normal_idx, attack_idx);   % Normal classified as attack
TN = C(normal_idx, normal_idx);   % Correctly predicted normal
FN = C(attack_idx, normal_idx);   % Attack classified as normal

% Calculate metrics
precision = TP / (TP + FP);
recall = TP / (TP + FN);
specificity = TN / (TN + FP);
f1_score = 2 * (precision * recall) / (precision + recall);
false_positive_rate = FP / (FP + TN);

fprintf('     Accuracy:    %.3f (%.2f%%)\n', accuracy, accuracy * 100);
fprintf('     Precision:   %.3f (What %% of predicted attacks are real)\n', precision);
fprintf('     Recall:      %.3f (What %% of real attacks are detected)\n', recall);
fprintf('     Specificity: %.3f (What %% of normal traffic is correctly identified)\n', specificity);
fprintf('     F1-Score:    %.3f (Harmonic mean of precision and recall)\n', f1_score);
fprintf('     False Positive Rate: %.3f (%.2f%%)\n', false_positive_rate, false_positive_rate * 100);

% Feature importance
feature_importance = rf_model.OOBPermutedPredictorDeltaError;
[sorted_importance, sort_idx] = sort(feature_importance, 'descend');

fprintf('\n   Top 10 Most Important Features for Binary Classification:\n');
for i = 1:min(10, length(feature_cols))
    feat_idx = sort_idx(i);
    fprintf('     %d. %s: %.4f\n', i, feature_cols{feat_idx}, sorted_importance(i));
end

%% Save Model and Metadata
fprintf('\n6. Saving binary model...\n');

timestamp = datestr(now, 'yyyymmdd_HHMMSS');
base_filename = sprintf('bluetooth_mesh_ids_binary_rf_%s', timestamp);

% Save the TreeBagger model
model_file = fullfile(MODELS_DIR, [base_filename, '.mat']);
save(model_file, 'rf_model', 'feature_cols', 'unique_classes', 'training_time', ...
     'accuracy', 'oob_error', 'precision', 'recall', 'f1_score', 'specificity');
fprintf('   ✅ Model saved to: %s\n', model_file);

% Save model parameters
params = struct();
params.model_type = 'MATLAB_TreeBagger_Binary';
params.num_trees = NUM_TREES;
params.min_leaf_size = MIN_LEAF_SIZE;
params.num_features_sample = NUM_FEATURES_SAMPLE;
params.feature_names = feature_cols;
params.class_names = unique_classes;  % Only 'ATTACK' and 'NORMAL'
params.training_samples = length(y_train);
params.validation_samples = length(y_val);
params.total_samples = length(y_binary);
params.accuracy = accuracy;
params.precision = precision;
params.recall = recall;
params.specificity = specificity;
params.f1_score = f1_score;
params.false_positive_rate = false_positive_rate;
params.oob_error = oob_error;
params.training_time = training_time;
params.feature_importance = feature_importance;
params.timestamp = timestamp;
params.num_source_files = length(files);
params.source_files = {files.name};
params.classification_type = 'binary';

params_file = fullfile(MODELS_DIR, sprintf('matlab_params_binary_%s.json', timestamp));
json_str = jsonencode(params);
fid = fopen(params_file, 'w');
fprintf(fid, '%s', json_str);
fclose(fid);
fprintf('   ✅ Parameters saved to: %s\n', params_file);

%% Create Binary Prediction Function
fprintf('\n7. Creating binary prediction function...\n');

prediction_function_code = sprintf(['function [is_attack, confidence] = predictBinaryAttackMATLAB(model, features)\n' ...
    '%% Predict attack using Binary MATLAB Random Forest model\n' ...
    '%% Inputs:\n' ...
    '%%   model - TreeBagger model (binary classifier)\n' ...
    '%%   features - 1x%d feature vector\n' ...
    '%% Outputs:\n' ...
    '%%   is_attack - boolean, true if attack detected, false if normal\n' ...
    '%%   confidence - double, prediction confidence [0,1]\n\n' ...
    'try\n' ...
    '    %% Make prediction\n' ...
    '    [prediction, scores] = predict(model, features);\n' ...
    '    \n' ...
    '    %% Extract results\n' ...
    '    attack_label = prediction{1};\n' ...
    '    \n' ...
    '    %% Determine if attack based on prediction\n' ...
    '    is_attack = strcmp(attack_label, ''ATTACK'');\n' ...
    '    \n' ...
    '    %% Get confidence score\n' ...
    '    %% scores contains probabilities for each class\n' ...
    '    %% Find which column corresponds to ''ATTACK''\n' ...
    '    if strcmp(model.ClassNames{1}, ''ATTACK'')\n' ...
    '        attack_score_idx = 1;\n' ...
    '    else\n' ...
    '        attack_score_idx = 2;\n' ...
    '    end\n' ...
    '    \n' ...
    '    %% Confidence is the probability of the predicted class\n' ...
    '    if is_attack\n' ...
    '        confidence = scores(attack_score_idx);\n' ...
    '    else\n' ...
    '        confidence = scores(3 - attack_score_idx);  %% Other class\n' ...
    '    end\n' ...
    '    \n' ...
    '    %% Ensure confidence is in valid range\n' ...
    '    confidence = max(0.1, min(0.99, confidence));\n' ...
    '    \n' ...
    'catch ME\n' ...
    '    %% Fallback in case of error\n' ...
    '    warning(''Binary prediction failed: %%s'', ME.message);\n' ...
    '    is_attack = false;\n' ...
    '    confidence = 0.5;\n' ...
    'end\n' ...
    'end'], length(feature_cols));

prediction_file = fullfile(MODELS_DIR, 'predictBinaryAttackMATLAB.m');
fid = fopen(prediction_file, 'w');
fprintf(fid, '%s', prediction_function_code);
fclose(fid);
fprintf('   ✅ Binary prediction function saved to: %s\n', prediction_file);

%% Integration Instructions
fprintf('\n8. Integration with your simulation:\n');
fprintf('   To use this binary model in your simulateMeshIDS.m:\n\n');
fprintf('   1. Load the model:\n');
fprintf('      load(''%s'');\n\n', model_file);
fprintf('   2. Update your IDS initialization:\n');
fprintf('      ids_model.rf_model = rf_model;\n');
fprintf('      ids_model.model_loaded = true;\n');
fprintf('      ids_model.model_type = ''MATLAB_BINARY'';\n\n');
fprintf('   3. Use the binary prediction function:\n');
fprintf('      [is_attack, confidence] = predictBinaryAttackMATLAB(rf_model, features);\n\n');

%% Model Testing
fprintf('\n9. Testing binary model with sample data...\n');

% Test with samples from validation set
test_indices = randsample(length(y_val), min(10, length(y_val)));

fprintf('   Sample Binary Predictions:\n');
correct_predictions = 0;
for i = 1:length(test_indices)
    idx = test_indices(i);
    test_features = X_val(idx, :);
    true_label = y_val{idx};
    
    [pred_label, pred_scores] = predict(rf_model, test_features);
    
    % Find attack score
    if strcmp(rf_model.ClassNames{1}, 'ATTACK')
        attack_score = pred_scores(1);
    else
        attack_score = pred_scores(2);
    end
    
    is_correct = strcmp(true_label, pred_label{1});
    if is_correct
        correct_predictions = correct_predictions + 1;
    end
    
    fprintf('     Sample %d: True=%s, Predicted=%s, AttackProb=%.3f %s\n', ...
        i, true_label, pred_label{1}, attack_score, ...
        ternary(is_correct, '✓', '✗'));
end

fprintf('   Sample accuracy: %d/%d (%.1f%%)\n', ...
    correct_predictions, length(test_indices), ...
    (correct_predictions/length(test_indices))*100);

%% Summary
fprintf('\n=========================================================\n');
fprintf('✅ Binary Random Forest Model Building Complete!\n');
fprintf('=========================================================\n');
fprintf('Model Summary:\n');
fprintf('  - Algorithm: Binary Random Forest (TreeBagger)\n');
fprintf('  - Trees: %d\n', NUM_TREES);
fprintf('  - Features: %d\n', length(feature_cols));
fprintf('  - Classes: 2 (ATTACK, NORMAL)\n');
fprintf('  - Total Samples: %d (from %d files)\n', length(y_binary), length(files));
fprintf('  - Training Samples: %d\n', length(y_train));
fprintf('  - Validation Samples: %d\n', length(y_val));
fprintf('\nPerformance Metrics:\n');
fprintf('  - Validation Accuracy: %.2f%%\n', accuracy * 100);
fprintf('  - Precision: %.3f\n', precision);
fprintf('  - Recall: %.3f\n', recall);
fprintf('  - F1-Score: %.3f\n', f1_score);
fprintf('  - Specificity: %.3f\n', specificity);
fprintf('  - False Positive Rate: %.3f\n', false_positive_rate);
fprintf('  - OOB Error: %.4f\n', oob_error);
fprintf('  - Training Time: %.2f seconds\n', training_time);
fprintf('\nFiles Created:\n');
fprintf('  - Model: %s\n', model_file);
fprintf('  - Parameters: %s\n', params_file);
fprintf('  - Prediction Function: %s\n', prediction_file);
fprintf('\nNext Steps:\n');
fprintf('  1. Load the binary model in your simulation\n');
fprintf('  2. Use predictBinaryAttackMATLAB() for simpler attack detection\n');
fprintf('  3. Run simulation and monitor false positive rate\n');
fprintf('=========================================================\n');

% Helper function for ternary operator
function result = ternary(condition, true_val, false_val)
    if condition
        result = true_val;
    else
        result = false_val;
    end
end
