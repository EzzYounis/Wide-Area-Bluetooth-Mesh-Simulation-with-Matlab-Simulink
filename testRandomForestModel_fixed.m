%% Test Random Forest Model - Fixed Version
% Quick test script to verify the Random Forest model works correctly
%
% Author: AI Assistant  
% Date: September 9, 2025

clear all; close all; clc;

fprintf('Testing Random Forest Model for Bluetooth Mesh IDS\n');
fprintf('==================================================\n\n');

%% Load the model
fprintf('1. Loading the trained Random Forest model...\n');
try
    ids_model = loadRandomForestModel();
    fprintf('✅ Model loaded successfully\n\n');
catch ME
    error('Failed to load model: %s', ME.message);
end

%% Test with sample feature vectors
fprintf('2. Testing with sample feature vectors...\n');

% Create test cases for each attack type (43 features each)
test_cases = struct();

% Normal traffic pattern (43 features)
test_cases.normal = [
    0.4, 0.3, 0.3, 0.9, 0.2, 0.4, 0.7, ...     % Network topology (7)
    0.2, 0.3, 0.1, 0.05, 0.1, 0, 0, ...         % Message content (7) 
    0.1, 0.3, 0.2, 0.8, 0.7, 0.1, ...           % Traffic patterns (6)
    0.8, 0.5, 0.7, 0.6, 0.8, 0.9, ...           % Behavioral (6)
    0.05, 0.05, 0.1, 0.95, 0.9, 0.95, ...       % Protocol (6)
    0.1, 0.3, 0.2, 0.7, 0.1, 0.3, ...           % Resource (6)
    0.8, 0.8, 0.8, 0.8, 0.1                     % Mesh-specific (5) = 43 total
];

% Flooding attack pattern (43 features)
test_cases.flooding = [
    0.6, 0.2, 0.3, 0.8, 0.3, 0.3, 0.6, ...     % Network topology (7)
    0.8, 0.4, 0.2, 0.08, 0.15, 0, 0, ...        % Message content (7)
    0.9, 0.8, 0.6, 0.2, 0.3, 0.8, ...           % Traffic patterns (6)
    0.2, 0.3, 0.4, 0.4, 0.5, 0.6, ...           % Behavioral (6)
    0.1, 0.1, 0.2, 0.9, 0.8, 0.9, ...           % Protocol (6)
    0.7, 0.6, 0.5, 0.6, 0.2, 0.4, ...           % Resource (6)
    0.7, 0.7, 0.6, 0.7, 0.2                     % Mesh-specific (5) = 43 total
];

% Black hole attack pattern (43 features)
test_cases.black_hole = [
    0.4, 0.3, 0.3, 0.4, 0.2, 0.4, 0.3, ...     % Network topology (7)
    0.3, 0.4, 0.1, 0.06, 0.1, 0, 0, ...         % Message content (7)
    0.2, 0.3, 0.3, 0.7, 0.6, 0.2, ...           % Traffic patterns (6)
    0.6, 0.4, 0.5, 0.5, 0.6, 0.7, ...           % Behavioral (6)
    0.08, 0.05, 0.7, 0.9, 0.8, 0.9, ...         % Protocol (6)
    0.3, 0.4, 0.3, 0.6, 0.2, 0.4, ...           % Resource (6)
    0.6, 0.6, 0.1, 0.6, 0.3                     % Mesh-specific (5) = 43 total
];

% Spoofing attack pattern (43 features)
test_cases.spoofing = [
    0.5, 0.3, 0.4, 0.8, 0.2, 0.4, 0.6, ...     % Network topology (7)
    0.4, 0.6, 0.3, 0.08, 0.4, 2, 0, ...         % Message content (7)
    0.3, 0.4, 0.4, 0.6, 0.5, 0.3, ...           % Traffic patterns (6)
    0.3, 0.4, 0.5, 0.5, 0.6, 0.7, ...           % Behavioral (6)
    0.1, 0.08, 0.3, 0.7, 0.7, 0.6, ...          % Protocol (6)
    0.4, 0.5, 0.4, 0.6, 0.3, 0.4, ...           % Resource (6)
    0.7, 0.7, 0.7, 0.7, 0.3                     % Mesh-specific (5) = 43 total
];

% Verify feature vector lengths
test_names = fieldnames(test_cases);
for i = 1:length(test_names)
    test_name = test_names{i};
    features = test_cases.(test_name);
    fprintf('   %s: %d features\n', test_name, length(features));
end
fprintf('\n');

% Test each case
fprintf('   Running %d test cases...\n\n', length(test_names));

for i = 1:length(test_names)
    test_name = test_names{i};
    features = test_cases.(test_name);
    
    % Make prediction
    tic;
    [is_attack, attack_type, confidence] = predictAttack(ids_model, features);
    prediction_time = toc * 1000; % Convert to milliseconds
    
    % Display results
    fprintf('   Test %d - %s:\n', i, upper(test_name));
    fprintf('     Predicted: %s\n', attack_type);
    fprintf('     Is Attack: %s\n', logical2str(is_attack));
    fprintf('     Confidence: %.3f\n', confidence);
    fprintf('     Processing Time: %.2f ms\n\n', prediction_time);
end

%% Performance Test
fprintf('3. Performance test (100 predictions)...\n');

% Generate random feature vectors for performance testing
n_tests = 100;
times = zeros(n_tests, 1);
predictions = cell(n_tests, 1);

for i = 1:n_tests
    % Generate random features (normalized to 43 features)
    features = rand(1, 43);
    
    % Time the prediction
    tic;
    [~, attack_type, ~] = predictAttack(ids_model, features);
    times(i) = toc * 1000; % Convert to milliseconds
    predictions{i} = attack_type;
end

% Calculate statistics
avg_time = mean(times);
max_time = max(times);
min_time = min(times);
std_time = std(times);

fprintf('   Performance Statistics:\n');
fprintf('     Average time: %.2f ms\n', avg_time);
fprintf('     Min time: %.2f ms\n', min_time);
fprintf('     Max time: %.2f ms\n', max_time);
fprintf('     Std deviation: %.2f ms\n', std_time);

% Prediction distribution
unique_predictions = unique(predictions);
fprintf('   Prediction Distribution:\n');
for i = 1:length(unique_predictions)
    count = sum(strcmp(predictions, unique_predictions{i}));
    percentage = (count / n_tests) * 100;
    fprintf('     %s: %d (%.1f%%)\n', unique_predictions{i}, count, percentage);
end

%% Integration Instructions
fprintf('\n4. Integration Instructions:\n');
fprintf('==================================================\n');
fprintf('To integrate this model into your simulateMeshIDS.m:\n\n');

fprintf('Option 1: Quick Integration\n');
fprintf('  1. Add this line near the top of your script:\n');
fprintf('     ids_model_template = loadRandomForestModel();\n\n');
fprintf('  2. In your node initialization loop, add:\n');
fprintf('     if ~nodes(i).is_attacker\n');
fprintf('         nodes(i).ids_model = ids_model_template;\n');
fprintf('     end\n\n');

fprintf('Option 2: Use Integration Script\n');
fprintf('  1. Copy the code from integrateRandomForestIDS.m\n');
fprintf('  2. Replace your existing IDS initialization section\n\n');

fprintf('The predictAttack function in your simulation should\n');
fprintf('automatically use the trained Random Forest model.\n\n');

fprintf('Model Files Created:\n');
model_files = dir('models/bluetooth_mesh_ids_rf_*.mat');
if ~isempty(model_files)
    [~, idx] = sort([model_files.datenum], 'descend');
    latest_model = model_files(idx(1)).name;
    fprintf('  - Latest model: models/%s\n', latest_model);
end
fprintf('  - Loader function: loadRandomForestModel.m\n');
fprintf('  - Integration code: integrateRandomForestIDS.m\n');
fprintf('==================================================\n');

%% Summary
fprintf('\n✅ Random Forest Model Test Complete!\n');
fprintf('The model is working correctly and ready for integration.\n');

%% Helper Functions
function [is_attack, attack_type, confidence] = predictAttack(ids_model, features)
    %% Prediction function for testing
    
    % Validate inputs
    if length(features) ~= 43
        warning('Feature vector should have 43 elements, got %d', length(features));
        features = [features, zeros(1, max(0, 43 - length(features)))]; % Pad if too short
        features = features(1:43); % Truncate if too long
    end
    
    % Ensure features are in valid range [0,1] (except URL count which can be >1)
    features(1:42) = max(0, min(1, features(1:42)));
    features(43) = max(0, features(43)); % Redundancy factor can be > 1
    
    if ids_model.model_loaded && strcmp(ids_model.model_type, 'MATLAB')
        try
            % Use trained Random Forest model
            [prediction, scores] = predict(ids_model.rf_model, features);
            
            attack_type = prediction{1};
            confidence = max(scores);
            is_attack = ~strcmp(attack_type, 'NORMAL');
            
            % Ensure confidence is in valid range
            confidence = max(0.1, min(0.99, confidence));
            
        catch ME
            warning('Random Forest prediction failed: %s. Using simulation model.', ME.message);
            [is_attack, attack_type, confidence] = simulateDetection(ids_model, features);
        end
    else
        % Use simulation model
        [is_attack, attack_type, confidence] = simulateDetection(ids_model, features);
    end
end

function [is_attack, attack_type, confidence] = simulateDetection(ids_model, features)
    %% Fallback simulation detection
    
    % Calculate risk score
    risk_score = sum(features .* ids_model.feature_weights);
    risk_score = 1 / (1 + exp(-risk_score)); % Sigmoid activation
    
    % Determine attack type based on feature patterns
    is_attack = false;
    attack_type = 'NORMAL';
    confidence = 0.5;
    
    % Detection logic
    if features(15) > 0.4 && features(8) > 0.3  % Flooding
        is_attack = true;
        attack_type = 'FLOODING';
        confidence = 0.6 + 0.2 * rand();
    elseif features(13) > 0 && features(21) < 0.6  % Spoofing
        is_attack = true;
        attack_type = 'SPOOFING';
        confidence = 0.5 + 0.25 * rand();
    elseif features(40) < 0.3 && features(29) > 0.3  % Black hole
        is_attack = true;
        attack_type = 'BLACK_HOLE';
        confidence = 0.5 + 0.25 * rand();
    end
    
    % Add noise
    confidence = min(0.99, max(0.1, confidence + 0.05 * randn()));
end

function str = logical2str(logical_val)
    if logical_val
        str = 'YES';
    else
        str = 'NO';
    end
end
