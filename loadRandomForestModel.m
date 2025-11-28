function ids_model = loadRandomForestModel(model_path)
%% Load Random Forest Model for IDS
% This function loads a trained Random Forest model for use in the
% Bluetooth Mesh IDS simulation
%
% Inputs:
%   model_path - (optional) path to the .mat file containing the model
%                If not provided, uses the most recent model
%
% Outputs:
%   ids_model - struct containing the loaded model and metadata
%
% Author: AI Assistant
% Date: September 9, 2025

if nargin < 1 || isempty(model_path)
    % Find the most recent model file
    models_dir = 'models';
    
    % First try to find binary models
    binary_pattern = fullfile(models_dir, 'bluetooth_mesh_ids_binary_rf_*.mat');
    binary_files = dir(binary_pattern);
    
    % Fallback to multi-class models if no binary models found
    multiclass_pattern = fullfile(models_dir, 'bluetooth_mesh_ids_rf_*.mat');
    multiclass_files = dir(multiclass_pattern);
    
    % Prefer binary models, but use multi-class if binary not available
    if ~isempty(binary_files)
        model_files = binary_files;
        fprintf('Found %d binary model(s)\n', length(binary_files));
    elseif ~isempty(multiclass_files)
        model_files = multiclass_files;
        fprintf('No binary models found, using multi-class model\n');
    else
        error('No Random Forest model files found in %s', models_dir);
    end
    
    % Sort by date and get the most recent
    [~, idx] = sort([model_files.datenum], 'descend');
    model_path = fullfile(model_files(idx(1)).folder, model_files(idx(1)).name);
    fprintf('Loading most recent model: %s\n', model_files(idx(1)).name);
end

% Load the model
try
    % Suppress TreeBagger output during loading
    original_state = warning('query', 'all');
    warning('off', 'all');
    
    model_data = load(model_path);
    fprintf('✅ Model loaded successfully from: %s\n', model_path);
    
    % Restore warning state
    warning(original_state);
catch ME
    % Restore warning state even if loading fails
    if exist('original_state', 'var')
        warning(original_state);
    end
    error('Failed to load model from %s: %s', model_path, ME.message);
end

% Create IDS model structure
ids_model = struct();

% Suppress any TreeBagger output during model structure creation
original_state = warning('query', 'all');
warning('off', 'all');

% Core model components
ids_model.rf_model = model_data.rf_model;
ids_model.feature_names = model_data.feature_cols;
ids_model.class_names = model_data.unique_classes;

% Restore warning state
warning(original_state);

% Model metadata
ids_model.model_loaded = true;
ids_model.model_type = 'MATLAB';
ids_model.model_path = model_path;
ids_model.accuracy = model_data.accuracy;
ids_model.oob_error = model_data.oob_error;
ids_model.training_time = model_data.training_time;

% Feature weights for simulation fallback
ids_model.feature_weights = ones(1, length(model_data.feature_cols)) / length(model_data.feature_cols);

% Detection thresholds
ids_model.confidence_threshold = 0.6;
ids_model.attack_threshold = 0.5;

% Hybrid mode settings (for compatibility with your existing code)
ids_model.hybrid_mode = false; % Set to true if you want to use hybrid detection
ids_model.fusion_weights = struct('rule_weight', 0.3, 'ai_weight', 0.7);

% Create detection rules (for hybrid mode)
ids_model.rules = createDetectionRules();

% Performance tracking
ids_model.total_predictions = 0;
ids_model.correct_predictions = 0;
ids_model.prediction_times = [];

fprintf('Model Configuration:\n');
fprintf('  - Type: %s\n', ids_model.model_type);
fprintf('  - Features: %d\n', length(ids_model.feature_names));
fprintf('  - Classes: %s\n', strjoin(ids_model.class_names, ', '));
fprintf('  - Validation Accuracy: %.2f%%\n', ids_model.accuracy * 100);
fprintf('  - OOB Error: %.4f\n', ids_model.oob_error);
fprintf('  - Hybrid Mode: %s\n', logical2str(ids_model.hybrid_mode));

end

function rules = createDetectionRules()
%% Create detection rules for hybrid mode
% Returns the same rules structure as in your simulation code

rules = struct();

% Rule 1: Flooding Detection (normalized thresholds for 0-1 feature range)
rules.flooding = struct();
rules.flooding.message_freq_threshold = 0.3; % 30% of max frequency
rules.flooding.message_size_threshold = 0.2; % 20% of max size  
rules.flooding.burst_window = 60; % seconds
rules.flooding.confidence = 0.7;

% Rule 2: Spoofing Detection
rules.spoofing = struct();
rules.spoofing.suspicious_url_count = 1;
rules.spoofing.emergency_keyword_abuse = 3;
rules.spoofing.sender_reputation_threshold = 0.3;
rules.spoofing.confidence = 0.85;

% Rule 3: Resource Exhaustion Detection (normalized thresholds)
rules.resource_exhaustion = struct();
rules.resource_exhaustion.message_size_threshold = 0.3; % 30% of max size
rules.resource_exhaustion.frequency_threshold = 0.2; % 20% of max frequency
rules.resource_exhaustion.battery_impact_threshold = 0.5; % 50% battery impact
rules.resource_exhaustion.confidence = 0.6;

% Rule 4: Black Hole Detection
rules.black_hole = struct();
rules.black_hole.forwarding_threshold = 0.2; % Low forwarding behavior
rules.black_hole.routing_anomaly_threshold = 0.4; % High routing anomalies
rules.black_hole.confidence = 0.75;

end

function str = logical2str(logical_val)
%% Convert logical to string
if logical_val
    str = 'enabled';
else
    str = 'disabled';
end
end
