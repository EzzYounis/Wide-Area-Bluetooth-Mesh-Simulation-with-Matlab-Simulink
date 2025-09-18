%% Build Random Forest Model for Bluetooth Mesh IDS
% This script builds a Random Forest model from your training data
% and saves it in a format that MATLAB can use in your simulation
%
% Author: AI Assistant
% Date: September 9, 2025

clear all; close all; clc;

%% Configuration
TRAINING_DATA_DIR = 'training_data';
MODELS_DIR = 'models';
USE_ALL_DATA = true; % Using both balanced and unbalanced datasets
VALIDATION_SPLIT = 0.2; % 20% for validation
RANDOM_SEED = 42;

% Model hyperparameters (adjusted for very large combined dataset)
NUM_TREES = 500; % Increased for much larger dataset
MIN_LEAF_SIZE = 2; % Reduced for better granularity with extensive data
MAX_NUM_SPLITS = []; % Let MATLAB decide optimal splits

fprintf('Building Random Forest Model for Bluetooth Mesh IDS\n');
fprintf('==================================================\n\n');

%% Create models directory if it doesn't exist
if ~exist(MODELS_DIR, 'dir')
    mkdir(MODELS_DIR);
end

%% Find and Load Training Data
fprintf('1. Loading training data...\n');

% Get list of available datasets (both balanced and unbalanced)
balanced_pattern = fullfile(TRAINING_DATA_DIR, 'balanced_feature_dataset_*.csv');
unbalanced_pattern = fullfile(TRAINING_DATA_DIR, 'feature_dataset_*.csv');

balanced_files = dir(balanced_pattern);
unbalanced_files = dir(unbalanced_pattern);

% Combine all files
files = [balanced_files; unbalanced_files];

if isempty(files)
    error('No training data files found in %s', TRAINING_DATA_DIR);
end

% Sort files by date
[~, idx] = sort([files.datenum], 'descend');
files = files(idx);

fprintf('   Found %d balanced dataset files\n', length(balanced_files));
fprintf('   Found %d unbalanced dataset files\n', length(unbalanced_files));
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

%% Data Preprocessing
fprintf('\n2. Preprocessing data...\n');

% Identify feature columns (exclude metadata columns)
metadata_cols = {'message_id', 'timestamp', 'source_id', 'destination_id', 'is_attack', 'source_file'};
feature_cols = setdiff(data.Properties.VariableNames, [metadata_cols, {'attack_type'}]);

% Extract features and labels
X = table2array(data(:, feature_cols));
y = data.attack_type;

% Convert categorical labels to cell array if needed
if iscategorical(y)
    y = cellstr(y);
end

% Display class distribution
unique_classes = unique(y);
fprintf('   Class distribution:\n');
total_samples = length(y);
for i = 1:length(unique_classes)
    count = sum(strcmp(y, unique_classes{i}));
    percentage = (count / total_samples) * 100;
    fprintf('     %s: %d (%.1f%%)\n', unique_classes{i}, count, percentage);
end

% Check for missing values
missing_count = sum(any(isnan(X), 2));
if missing_count > 0
    fprintf('   ⚠️  Found %d samples with missing values, removing them\n', missing_count);
    valid_idx = ~any(isnan(X), 2);
    X = X(valid_idx, :);
    y = y(valid_idx);
end

% Check for infinite values
inf_count = sum(any(isinf(X), 2));
if inf_count > 0
    fprintf('   ⚠️  Found %d samples with infinite values, removing them\n', inf_count);
    valid_idx = ~any(isinf(X), 2);
    X = X(valid_idx, :);
    y = y(valid_idx);
end

fprintf('   ✅ Final dataset: %d samples, %d features\n', size(X, 1), size(X, 2));

% Calculate number of features to sample (sqrt of total features)
NUM_FEATURES_SAMPLE = round(sqrt(size(X, 2)));

%% Train-Validation Split
fprintf('\n3. Splitting data for training and validation...\n');

rng(RANDOM_SEED); % Set random seed for reproducibility

% Stratified split to maintain class distribution
n_samples = length(y);
train_idx = [];
val_idx = [];

for i = 1:length(unique_classes)
    class_name = unique_classes{i};
    class_idx = find(strcmp(y, class_name));
    n_class = length(class_idx);
    
    n_val = round(n_class * VALIDATION_SPLIT);
    val_class_idx = class_idx(randperm(n_class, n_val));
    train_class_idx = setdiff(class_idx, val_class_idx);
    
    train_idx = [train_idx; train_class_idx];
    val_idx = [val_idx; val_class_idx];
end

% Create training and validation sets
X_train = X(train_idx, :);
y_train = y(train_idx);
X_val = X(val_idx, :);
y_val = y(val_idx);

fprintf('   Training set: %d samples\n', length(y_train));
fprintf('   Validation set: %d samples\n', length(y_val));

%% Build Random Forest Model
fprintf('\n4. Training Random Forest model...\n');
fprintf('   Parameters:\n');
fprintf('     - Number of trees: %d\n', NUM_TREES);
fprintf('     - Minimum leaf size: %d\n', MIN_LEAF_SIZE);
fprintf('     - Features per split: %d (sqrt of %d)\n', NUM_FEATURES_SAMPLE, size(X, 2));

tic;
try
    % Create TreeBagger (Random Forest) model
    fprintf('   Training Random Forest with %d trees...\n', NUM_TREES);
    
    % Temporarily capture and suppress output during training
    original_formatspec = get(0, 'Format');
    evalc_cmd = sprintf(['rf_model = TreeBagger(%d, X_train, y_train, ' ...
        '''Method'', ''classification'', ' ...
        '''MinLeafSize'', %d, ' ...
        '''NumVariablesToSample'', %d, ' ...
        '''OOBPrediction'', ''on'', ' ...
        '''OOBPredictorImportance'', ''on'');'], ...
        NUM_TREES, MIN_LEAF_SIZE, NUM_FEATURES_SAMPLE);
    
    % Use evalc to capture and suppress output
    evalc(evalc_cmd);
    
    training_time = toc;
    fprintf('   ✅ Model trained successfully in %.2f seconds\n', training_time);
    
    % Display final OOB error summary (cleaner than the spam during training)
    final_oob_error = mean(rf_model.OOBPermutedPredictorDeltaError);
    fprintf('   📊 Final Out-of-Bag Error: %.4f (%.2f%% accuracy)\n', ...
        final_oob_error, (1 - final_oob_error) * 100);
    
catch ME
    error('Failed to train model: %s', ME.message);
end

%% Model Evaluation
fprintf('\n5. Evaluating model performance...\n');

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

% Per-class metrics
fprintf('\n   Per-class Performance:\n');
precision = zeros(length(order), 1);
recall = zeros(length(order), 1);
f1_score = zeros(length(order), 1);

for i = 1:length(order)
    tp = C(i, i);
    fp = sum(C(:, i)) - tp;
    fn = sum(C(i, :)) - tp;
    
    precision(i) = tp / (tp + fp);
    recall(i) = tp / (tp + fn);
    f1_score(i) = 2 * (precision(i) * recall(i)) / (precision(i) + recall(i));
    
    fprintf('     %s: Precision=%.3f, Recall=%.3f, F1=%.3f\n', ...
        order{i}, precision(i), recall(i), f1_score(i));
end

% Feature importance
feature_importance = rf_model.OOBPermutedPredictorDeltaError;
[sorted_importance, sort_idx] = sort(feature_importance, 'descend');

fprintf('\n   Top 10 Most Important Features:\n');
for i = 1:min(10, length(feature_cols))
    feat_idx = sort_idx(i);
    fprintf('     %d. %s: %.4f\n', i, feature_cols{feat_idx}, sorted_importance(i));
end

%% Save Model and Metadata
fprintf('\n6. Saving model...\n');

timestamp = datestr(now, 'yyyymmdd_HHMMSS');
base_filename = sprintf('bluetooth_mesh_ids_rf_%s', timestamp);

% Save the TreeBagger model
model_file = fullfile(MODELS_DIR, [base_filename, '.mat']);
save(model_file, 'rf_model', 'feature_cols', 'unique_classes', 'training_time', 'accuracy', 'oob_error');
fprintf('   ✅ Model saved to: %s\n', model_file);

% Save model parameters for Python compatibility
params = struct();
params.model_type = 'MATLAB_TreeBagger';
params.num_trees = NUM_TREES;
params.min_leaf_size = MIN_LEAF_SIZE;
params.num_features_sample = NUM_FEATURES_SAMPLE;
params.feature_names = feature_cols;
params.class_names = unique_classes;
params.training_samples = length(y_train);
params.validation_samples = length(y_val);
params.total_samples = length(y);
params.accuracy = accuracy;
params.oob_error = oob_error;
params.training_time = training_time;
params.feature_importance = feature_importance;
params.timestamp = timestamp;
params.num_source_files = length(files);
params.source_files = {files.name}; % List of all source files used
params.data_type = 'combined (balanced + unbalanced)';
params.num_balanced_files = length(balanced_files);
params.num_unbalanced_files = length(unbalanced_files);

params_file = fullfile(MODELS_DIR, sprintf('matlab_params_%s.json', timestamp));
json_str = jsonencode(params);
fid = fopen(params_file, 'w');
fprintf(fid, '%s', json_str);
fclose(fid);
fprintf('   ✅ Parameters saved to: %s\n', params_file);

%% Create Prediction Functions
fprintf('\n7. Creating prediction functions...\n');

% Create a simple prediction function
prediction_function_code = sprintf(['function [is_attack, attack_type, confidence] = predictAttackMATLAB(model, features)\n' ...
    '%% Predict attack using MATLAB Random Forest model\n' ...
    '%% Inputs:\n' ...
    '%%   model - TreeBagger model\n' ...
    '%%   features - 1x%d feature vector\n' ...
    '%% Outputs:\n' ...
    '%%   is_attack - boolean, true if attack detected\n' ...
    '%%   attack_type - string, type of attack or ''NORMAL''\n' ...
    '%%   confidence - double, prediction confidence [0,1]\n\n' ...
    'try\n' ...
    '    %% Make prediction\n' ...
    '    [prediction, scores] = predict(model, features);\n' ...
    '    \n' ...
    '    %% Extract results\n' ...
    '    attack_type = prediction{1};\n' ...
    '    confidence = max(scores);\n' ...
    '    is_attack = ~strcmp(attack_type, ''NORMAL'');\n' ...
    '    \n' ...
    '    %% Ensure confidence is in valid range\n' ...
    '    confidence = max(0.1, min(0.99, confidence));\n' ...
    '    \n' ...
    'catch ME\n' ...
    '    %% Fallback in case of error\n' ...
    '    warning(''Prediction failed: %%s'', ME.message);\n' ...
    '    is_attack = false;\n' ...
    '    attack_type = ''NORMAL'';\n' ...
    '    confidence = 0.5;\n' ...
    'end\n' ...
    'end'], length(feature_cols));

prediction_file = fullfile(MODELS_DIR, 'predictAttackMATLAB.m');
fid = fopen(prediction_file, 'w');
fprintf(fid, '%s', prediction_function_code);
fclose(fid);
fprintf('   ✅ Prediction function saved to: %s\n', prediction_file);

%% Integration Instructions
fprintf('\n8. Integration with your simulation:\n');
fprintf('   To use this model in your simulateMeshIDS.m:\n\n');
fprintf('   1. Load the model:\n');
fprintf('      load(''%s'');\n\n', model_file);
fprintf('   2. Update your IDS initialization in the simulation:\n');
fprintf('      ids_model.rf_model = rf_model;\n');
fprintf('      ids_model.model_loaded = true;\n');
fprintf('      ids_model.model_type = ''MATLAB'';\n\n');
fprintf('   3. The predictAttack function in your code should work with this model.\n\n');

%% Model Testing
fprintf('\n9. Testing model with sample data...\n');

% Test with a few samples from validation set
test_indices = randsample(length(y_val), min(5, length(y_val)));

fprintf('   Sample Predictions:\n');
for i = 1:length(test_indices)
    idx = test_indices(i);
    test_features = X_val(idx, :);
    true_label = y_val{idx};
    
    [pred_label, pred_scores] = predict(rf_model, test_features);
    pred_confidence = max(pred_scores);
    
    fprintf('     Sample %d: True=%s, Predicted=%s, Confidence=%.3f\n', ...
        i, true_label, pred_label{1}, pred_confidence);
end

%% Summary
fprintf('\n==================================================\n');
fprintf('✅ Random Forest Model Building Complete!\n');
fprintf('==================================================\n');
fprintf('Model Summary:\n');
fprintf('  - Algorithm: Random Forest (TreeBagger)\n');
fprintf('  - Trees: %d\n', NUM_TREES);
fprintf('  - Features: %d\n', length(feature_cols));
fprintf('  - Classes: %d (%s)\n', length(unique_classes), strjoin(unique_classes, ', '));
fprintf('  - Total Samples: %d (from %d files)\n', length(y), length(files));
fprintf('  - Training Samples: %d\n', length(y_train));
fprintf('  - Validation Samples: %d\n', length(y_val));
fprintf('  - Validation Accuracy: %.2f%%\n', accuracy * 100);
fprintf('  - OOB Error: %.4f\n', oob_error);
fprintf('  - Training Time: %.2f seconds\n', training_time);
fprintf('  - Data Type: combined (balanced + unbalanced)\n');
fprintf('\nSource Files Used:\n');
fprintf('  Balanced datasets: %d files\n', length(balanced_files));
fprintf('  Unbalanced datasets: %d files\n', length(unbalanced_files));
for i = 1:min(5, length(files))
    fprintf('  - %s\n', files(i).name);
end
if length(files) > 5
    fprintf('  - ... and %d more files\n', length(files) - 5);
end
fprintf('\nFiles Created:\n');
fprintf('  - Model: %s\n', model_file);
fprintf('  - Parameters: %s\n', params_file);
fprintf('  - Prediction Function: %s\n', prediction_file);
fprintf('\nNext Steps:\n');
fprintf('  1. Load the model in your simulation\n');
fprintf('  2. Update your IDS configuration\n');
fprintf('  3. Run your simulation to test the model\n');
fprintf('==================================================\n');
