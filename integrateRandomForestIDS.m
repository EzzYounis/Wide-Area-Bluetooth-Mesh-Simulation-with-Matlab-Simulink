%% Updated IDS Initialization for Random Forest Model
% Add this code to your simulateMeshIDS.m file to integrate the trained Random Forest model
% Replace the existing IDS initialization section with this code

%% Initialize IDS Models for Normal Nodes
fprintf('Initializing IDS models with trained Random Forest...\n');

% Load the trained Random Forest model
try
    ids_model_template = loadRandomForestModel(); % Uses most recent model
    fprintf('✅ Random Forest model loaded successfully\n');
catch ME
    warning('Failed to load Random Forest model: %s', ME.message);
    fprintf('⚠️  Falling back to simulation model\n');
    ids_model_template = createSimulationIDSModel(); % Fallback function
end

% Apply IDS model to all normal nodes
for i = 1:length(nodes)
    if ~nodes(i).is_attacker
        nodes(i).ids_model = ids_model_template;
        fprintf('IDS initialized for normal node %d\n', nodes(i).id);
    end
end

fprintf('IDS initialization complete.\n\n');

%% Functions for IDS Model Creation

function ids_model = createSimulationIDSModel()
    %% Fallback simulation model (original implementation)
    ids_model = struct();
    ids_model.model_loaded = false;
    ids_model.model_type = 'SIMULATION';
    
    % Feature weights for simulation (original implementation)
    ids_model.feature_weights = [
        0.1, 0.05, 0.08, 0.06, 0.04, 0.03, 0.05, ... % Network topology features
        0.15, 0.12, 0.08, 0.06, 0.2, 0.25, 0.1, ... % Message content features  
        0.3, 0.15, 0.1, 0.08, 0.06, 0.12, ... % Traffic pattern features
        0.18, 0.05, 0.04, 0.03, 0.02, 0.02, ... % Behavioral features
        0.08, 0.04, 0.15, 0.06, 0.03, 0.05, ... % Protocol features
        0.2, 0.12, 0.08, 0.06, 0.04, 0.03, ... % Resource features
        0.05, 0.08, 0.1, 0.15, 0.12, 0.06, 0.04 ... % Mesh-specific features
    ];
    
    % Ensure correct length (43 features)
    if length(ids_model.feature_weights) < 43
        ids_model.feature_weights(end+1:43) = 0.05; % Default weight for missing features
    elseif length(ids_model.feature_weights) > 43
        ids_model.feature_weights = ids_model.feature_weights(1:43);
    end
    
    % Normalize weights
    ids_model.feature_weights = ids_model.feature_weights / sum(ids_model.feature_weights);
    
    % Detection settings
    ids_model.confidence_threshold = 0.6;
    ids_model.attack_threshold = 0.5;
    
    % Hybrid mode settings
    ids_model.hybrid_mode = false;
    ids_model.fusion_weights = struct('rule_weight', 0.4, 'ai_weight', 0.6);
    ids_model.rules = createDetectionRules();
    
    fprintf('Using simulation IDS model (no trained model available)\n');
end

%% Enhanced Prediction Function for MATLAB Random Forest
function [is_attack, attack_type, confidence] = predictAttack(ids_model, features)
    %% Enhanced prediction function that works with both trained and simulation models
    
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
            
            % Update model statistics
            ids_model.total_predictions = ids_model.total_predictions + 1;
            
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
    %% Original simulation detection logic (fallback)
    
    % Calculate risk score using weighted features
    risk_score = sum(features .* ids_model.feature_weights);
    risk_score = 1 / (1 + exp(-risk_score)); % Sigmoid activation
    
    % Determine if it's an attack based on specific feature patterns
    is_attack = false;
    attack_type = 'NORMAL';
    confidence = 0.5;
    
    % Enhanced detection logic with lower thresholds for better sensitivity
    % Flooding detection (high message frequency + large size)
    if features(15) > 0.4 && features(8) > 0.3  % Reduced thresholds
        is_attack = true;
        attack_type = 'FLOODING';
        confidence = 0.6 + 0.2 * rand();
    % Spoofing detection (suspicious URLs + low reputation)  
    elseif features(13) > 0 && features(21) < 0.6  % Increased reputation threshold
        is_attack = true;
        attack_type = 'SPOOFING';
        confidence = 0.5 + 0.25 * rand();
    % Resource exhaustion detection (high battery impact + large messages)
    elseif features(33) > 0.5 && features(8) > 0.25  % Reduced thresholds
        is_attack = true;
        attack_type = 'RESOURCE_EXHAUSTION';
        confidence = 0.45 + 0.3 * rand();
    % Black hole detection (low forwarding + high routing anomaly)
    elseif features(40) < 0.3 && features(29) > 0.3  % Adjusted thresholds
        is_attack = true;
        attack_type = 'BLACK_HOLE';
        confidence = 0.5 + 0.25 * rand();
    % Adaptive flooding detection (variable patterns)
    elseif features(17) > 0.5 && features(19) < 0.4  % High variance, low regularity
        is_attack = true;
        attack_type = 'ADAPTIVE_FLOODING';
        confidence = 0.45 + 0.3 * rand();
    end
    
    % Add some noise to make it realistic
    confidence = min(0.99, max(0.1, confidence + 0.05 * randn()));
end

%% Model Performance Tracking
function logModelPerformance(ids_model, prediction_result, true_label, processing_time)
    %% Log model performance for analysis
    
    persistent performance_log;
    if isempty(performance_log)
        performance_log = struct('predictions', [], 'true_labels', {}, 'processing_times', []);
    end
    
    % Add to log
    performance_log.predictions(end+1) = prediction_result;
    performance_log.true_labels{end+1} = true_label;
    performance_log.processing_times(end+1) = processing_time;
    
    % Calculate running accuracy every 100 predictions
    if mod(length(performance_log.predictions), 100) == 0
        n = length(performance_log.predictions);
        correct = sum(strcmp({performance_log.predictions.attack_type}, performance_log.true_labels));
        accuracy = correct / n;
        avg_time = mean(performance_log.processing_times);
        
        fprintf('Model Performance Update (n=%d): Accuracy=%.2f%%, Avg Time=%.2fms\n', ...
            n, accuracy*100, avg_time);
    end
end

%% Usage Instructions:
% 1. Run buildRandomForestModel.m first to train the model
% 2. Replace your existing IDS initialization code with the code above
% 3. The predictAttack function will automatically use the trained model
% 4. If the trained model fails to load, it falls back to simulation mode

fprintf('✅ IDS integration code ready. Add this to your simulateMeshIDS.m file.\n');
