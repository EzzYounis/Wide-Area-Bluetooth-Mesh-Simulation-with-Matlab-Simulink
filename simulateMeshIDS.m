%% Bluetooth Mesh Network IDS Simulation
% AI-Assisted Intrusion Detection System for Bluetooth Mesh Networks
% Author: Research Simulation
% Date: 2024


clear all; close all; clc;

%% Simulation Parameters
global NUM_NORMAL_NODES NUM_ATTACK_NODES TOTAL_NODES MESSAGE_INTERVAL SIMULATION_TIME TRANSMISSION_RANGE AREA_SIZE ;
NUM_NORMAL_NODES = 35;
NUM_ATTACK_NODES = 6;
TOTAL_NODES = NUM_NORMAL_NODES + NUM_ATTACK_NODES;
MESSAGE_INTERVAL = 10; % seconds - REDUCED from 60 to generate more messages
SIMULATION_TIME = 50 * 60; % 5 minutes for better forwarding analysis
TRANSMISSION_RANGE = 50; % meterss
AREA_SIZE = 400; % 200x200 meter area

%% Initialize Global Variables
global simulation_data;
simulation_data = struct();
simulation_data.messages = struct([]);        % Empty struct array, NOT []
simulation_data.detections = struct([]);      % Empty struct array, NOT []
simulation_data.network_events = struct([])
simulation_data.statistics = struct();
simulation_data.current_time = 0;

%% Node Creation Functions
function node = createAttackerNode(id, x, y)
    node = struct();
    node.id = id;
    node.position = [x, y];
    node.is_attacker = true;
    node.battery_level = 0.9 + 0.1 * rand(); % 90-100%
    node.processing_power = 0.8 + 0.2 * rand(); % 80-100%
    node.neighbors = [];
    node.message_buffer = {};
    node.max_buffer_bytes = 4096; % Realistic buffer size limit (bytes)
    node.routing_table = containers.Map();
    node.reputation_scores = containers.Map();
    node.message_history = {};
    node.detection_stats = struct('tp', 0, 'fp', 0, 'tn', 0, 'fn', 0);
    node.is_active = true;
    
    % Attacker-specific properties
    strategies = {'FLOODING', 'ADAPTIVE_FLOODING', 'RESOURCE_EXHAUSTION', 'BLACK_HOLE', 'SPOOFING'};
    node.attack_strategy = strategies{randi(length(strategies))};
    node.attack_frequency = 5 + 5 * rand(); % REDUCED: 5-10 seconds between attacks
    node.last_attack_time = 0;
    node.target_nodes = [];
    node.message_cache = containers.Map();
    node.cache_duration = 20;
    node.attack_params = struct(); % Will be populated by advanced attacker function
    
    % Initialize tracking fields for dynamic features
    node.forwarded_count = 0;
    node.received_count = 0;
    node.last_position = [x, y]; % Initialize with current position
    node.total_distance_moved = 0; % Track cumulative movement
end

function node = createNormalNode(id, x, y)
    node = struct();
    node.id = id;
    node.position = [x, y];
    node.is_attacker = false;
    node.battery_level = 0.8 + 0.2 * rand(); % 80-100%
    node.processing_power = 0.7 + 0.3 * rand(); % 70-100%
    node.neighbors = [];
    node.message_buffer = {};
    node.max_buffer_bytes = 4096; % Realistic buffer size limit (bytes)
    node.routing_table = containers.Map();
    node.reputation_scores = containers.Map();
    node.message_history = {};
    node.detection_stats = struct('tp', 0, 'fp', 0, 'tn', 0, 'fn', 0);
    node.is_active = true;
    % Add these missing fields for consistency:
    node.attack_strategy = '';  % Empty for normal nodes
    node.attack_frequency = 0;  % 0 for normal nodes
    node.last_attack_time = 0;
    
    % Initialize tracking fields for dynamic features
    node.forwarded_count = 0;
    node.received_count = 0;
    node.last_position = [x, y]; % Initialize with current position
    node.total_distance_moved = 0; % Track cumulative movement
    node.target_nodes = [];
    node.message_cache = containers.Map();
    node.cache_duration = 20;
    node.attack_params = struct(); % Empty struct for normal nodes
    
    % Initialize tracking fields for dynamic features
    node.forwarded_count = 0;
    node.received_count = 0;
    node.last_position = [x, y]; % Initialize with current position
    node.total_distance_moved = 0; % Track cumulative movement
end

function node = createAdvancedAttackerNode(id, x, y)
    node = createAttackerNode(id, x, y); % Use base function
    
    % Enhanced attack strategies with specific parameters
    advanced_strategies = {
        'FLOODING', 'ADAPTIVE_FLOODING', 'RESOURCE_EXHAUSTION', 'BLACK_HOLE', 'SPOOFING'
    };
    node.attack_strategy = advanced_strategies{randi(length(advanced_strategies))};
    node.attack_params = struct();
    % Strategy-specific parameters
    switch node.attack_strategy
        case 'FLOODING'
            % Basic flooding: no extra params needed
        case 'ADAPTIVE_FLOODING'
            node.attack_params.flood_pattern = randi([1, 4]);
            node.attack_params.message_burst_size = 5 + randi(10);
            node.attack_params.burst_interval = 20 + randi(40);
        case 'RESOURCE_EXHAUSTION'
            node.attack_params.target_resource = randi([1, 3]); % Battery, Processing, Memory
            node.attack_params.exhaustion_rate = 0.1 + 0.2 * rand(); % 0.1-0.3 depletion rate
        case 'BLACK_HOLE'
            % No extra params needed for black hole
        case 'SPOOFING'
            % No extra params needed for spoofing
    end
    
    % Dynamic attack frequency based on strategy
    base_frequency = 8; % REDUCED from 30 to 8 seconds
    switch node.attack_strategy
        case 'ADAPTIVE_FLOODING'
            node.attack_frequency = base_frequency * 0.3; % More frequent (2-3 seconds)
        otherwise
            node.attack_frequency = base_frequency + randi(10); % 8-18 seconds
    end
end


function [x, y] = getGridPosition(node_index, total_nodes, area_size, transmission_range)
    % Calculate grid dimensions
    grid_size = ceil(sqrt(total_nodes));
    spacing = min(area_size / grid_size, transmission_range * 0.8); % 80% of transmission range
    
    % Add some padding from edges
    padding = spacing * 0.2;
    
    row = floor((node_index - 1) / grid_size);
    col = mod(node_index - 1, grid_size);
    
    x = padding + col * spacing + rand() * spacing * 0.3; % Add 30% randomness
    y = padding + row * spacing + rand() * spacing * 0.3;
    
    % Ensure within bounds
    x = min(max(x, 0), area_size);
    y = min(max(y, 0), area_size);
end

function ids_model = trainRandomForestModel(ids_model)
    try
        fprintf('Training Random Forest classifier...\n');
        
        % Generate training data (similar to your Python model)
        [X_train, y_train] = generateTrainingData(5000, ids_model.attack_types);
        
        % Create Random Forest using TreeBagger
        ids_model.rf_model = TreeBagger(100, X_train, y_train, ...
            'Method', 'classification', ...
            'NumPredictorsToSample', 'all', ...
            'MinLeafSize', 1, ...
            'InBagFraction', 0.7);
        
        ids_model.model_loaded = true;
        fprintf('Random Forest model trained successfully\n');
        
    catch ME
        fprintf('Failed to train Random Forest: %s\n', ME.message);
        fprintf('Using simplified simulation model instead\n');
        ids_model.model_loaded = false;
    end
end

%% Node Operation Functions
function node = updateNeighbors(node, all_nodes, transmission_range)
    node.neighbors = [];
    for i = 1:length(all_nodes)
        if all_nodes(i).id ~= node.id && all_nodes(i).is_active
            distance = norm(node.position - all_nodes(i).position);
            if distance <= transmission_range
                node.neighbors(end+1) = all_nodes(i).id;
            end
        end
    end
end

function [node, message] = sendMessage(node, content, msg_type, destination_id, current_time)
    if ~node.is_active || node.battery_level < 0.1
        message = [];
        return;
    end
    
    message = struct();
    message.id = generateMessageID();
    message.source_id = node.id;
    message.destination_id = destination_id;
    message.content = content;
    message.type = msg_type;
    message.timestamp = current_time;
    message.ttl = 10;
    message.hop_count = 0;
    message.route_path = {node.id};
    message.size_bytes = length(content);
        message.is_attack = node.is_attacker; % Any message from attacker is an attack
        % Add true attack attributes for data collection
        message.true_is_attack = node.is_attacker;
        if node.is_attacker && isfield(node, 'attack_strategy') && ~isempty(node.attack_strategy)
            message.true_attack_type = node.attack_strategy;
        elseif node.is_attacker
            message.true_attack_type = 'UNKNOWN_ATTACK';
        else
            message.true_attack_type = 'NORMAL';
        end
    cache_entry = struct();
    cache_entry.message = message;
    cache_entry.cache_time = current_time;
    cache_entry.forwarded_to = []; % Track which neighbors already received it
    
    node.message_cache(message.id) = cache_entry;

    % Add to global message log
    global simulation_data;
    
    % Safe way to add to struct array
    if isempty(simulation_data.messages)
        simulation_data.messages = message;
    else
        simulation_data.messages(end+1) = message;
    end
    
    % Consume battery
    node.battery_level = node.battery_level - 0.001;
    
    fprintf('Node %d sent message %s at time %.2f\n', node.id, message.id, current_time);
end

function [node, detection_result] = receiveMessage(node, message, current_time, sender_node)
    detection_result = [];
    if ~node.is_active || node.battery_level < 0.1
        return;
    end
    if nodeHasMessage(node, message.id)
        fprintf('Node %d already has message %s, ignoring duplicate\n', node.id, message.id);
        return;
    end
    cache_entry = struct();
    cache_entry.message = message;
    cache_entry.cache_time = current_time;
    cache_entry.forwarded_to = [];
    node.message_cache(message.id) = cache_entry;

    % Black hole attack: drop all received messages, do not buffer or forward
    if node.is_attacker && isfield(node, 'attack_strategy') && strcmp(node.attack_strategy, 'BLACK_HOLE')
        fprintf('BLACK HOLE: Node %d dropped message %s\n', node.id, message.id);
        return;
    end

    % Print message path
    fprintf('Message %s: From Node %d → To Node %d (new)\n', ...
        message.id, message.source_id, node.id);

    % Enforce buffer size limit (by total bytes)
    current_bytes = sum(cellfun(@(msg) length(msg.content), node.message_buffer));
    if current_bytes + length(message.content) > node.max_buffer_bytes
        fprintf('Node %d buffer full (bytes)! Dropping message %s\n', node.id, message.id);
        return;
    end
    % Store message in buffer
    node.message_buffer{end+1} = message;
    node.message_history{end+1} = message;

    % Update received count for forwarding behavior tracking
    node.received_count = node.received_count + 1;

    % If not attacker, run IDS detection
    if ~node.is_attacker
        [node, detection_result] = runIDSDetection(node, message, sender_node, current_time);
        logMessageDetails(message, detection_result, node, current_time);
    else
        % Even attackers should log received messages for completeness
        logMessageDetails(message, [], node, current_time);
        % Also log features for messages received by attackers
        logFeatureData(message, current_time, node, sender_node);
    end

    % Consume battery
    node.battery_level = node.battery_level - 0.0005;
end
%Detection Rules for Rule-based Detection
function rules = createDetectionRules()
    rules = struct();
    
    % Rule 1: Flooding Detection
    rules.flooding = struct();
    rules.flooding.message_freq_threshold = 10; % messages per minute
    rules.flooding.message_size_threshold = 500; % bytes
    rules.flooding.burst_window = 60; % seconds
    rules.flooding.confidence = 0.9;
    
    % Rule 2: Spoofing Detection
    rules.spoofing = struct();
    rules.spoofing.suspicious_url_count = 1;
    rules.spoofing.emergency_keyword_abuse = 3;
    rules.spoofing.sender_reputation_threshold = 0.3;
    rules.spoofing.confidence = 0.85;
    
    % Rule 3: Resource Exhaustion Detection (renamed from resource_drain)
    rules.resource_exhaustion = struct();
    rules.resource_exhaustion.message_size_threshold = 800;
    rules.resource_exhaustion.frequency_threshold = 5;
    rules.resource_exhaustion.battery_impact_threshold = 0.8;
    rules.resource_exhaustion.confidence = 0.8;
end
%Rule-based Detection
function [rule_result] = runRuleBasedDetection(node, message, sender_node, current_time, features)
    rules = node.ids_model.rules;
    rule_result = struct();
    rule_result.detected_attacks = {};
    rule_result.confidences = [];
    rule_result.overall_confidence = 0;
    rule_result.triggered_rules = {};
    
    % Rule 1: Flooding Detection
    if features(15) > rules.flooding.message_freq_threshold && ...
       features(8) > rules.flooding.message_size_threshold
        rule_result.detected_attacks{end+1} = 'FLOODING';
        rule_result.confidences(end+1) = rules.flooding.confidence;
        rule_result.triggered_rules{end+1} = 'flooding_detection';
        fprintf('RULE TRIGGER: Flooding detected (freq=%.1f, size=%d)\n', ...
            features(15), features(8));
    end
    
    % Rule 2: Spoofing Detection
    spoofing_score = 0;
    if features(13) >= rules.spoofing.suspicious_url_count
        spoofing_score = spoofing_score + 0.4;
    end
    if features(12) >= rules.spoofing.emergency_keyword_abuse
        spoofing_score = spoofing_score + 0.3;
    end
    if features(21) <= rules.spoofing.sender_reputation_threshold
        spoofing_score = spoofing_score + 0.3;
    end
    
    if spoofing_score >= 0.6
        rule_result.detected_attacks{end+1} = 'SPOOFING';
        rule_result.confidences(end+1) = rules.spoofing.confidence * spoofing_score;
        rule_result.triggered_rules{end+1} = 'spoofing_detection';
        fprintf('RULE TRIGGER: Spoofing detected (score=%.2f)\n', spoofing_score);
    end
    
    % Rule 3: Resource Exhaustion Detection
    if features(8) > rules.resource_exhaustion.message_size_threshold && ...
       features(15) > rules.resource_exhaustion.frequency_threshold && ...
       features(33) > rules.resource_exhaustion.battery_impact_threshold
        rule_result.detected_attacks{end+1} = 'RESOURCE_EXHAUSTION';
        rule_result.confidences(end+1) = rules.resource_exhaustion.confidence;
        rule_result.triggered_rules{end+1} = 'resource_exhaustion_detection';
        fprintf('RULE TRIGGER: Resource exhaustion detected\n');
    end
    
    % Calculate overall rule confidence
    if ~isempty(rule_result.confidences)
        rule_result.overall_confidence = max(rule_result.confidences);
        rule_result.primary_attack = rule_result.detected_attacks{find(rule_result.confidences == rule_result.overall_confidence, 1)};
    else
        rule_result.primary_attack = 'NORMAL';
        rule_result.overall_confidence = 0;
    end
end


function [final_result] = fuseDetectionResults(rule_result, ai_result, fusion_weights)
    final_result = struct();
    
    % Determine if attack detected by either system
    rule_attack = ~strcmp(rule_result.primary_attack, 'NORMAL') && rule_result.overall_confidence > 0.5;
    ai_attack = ai_result.is_attack && ai_result.confidence > 0.5;
    
    % Fusion logic
    if rule_attack && ai_attack
        % Both agree - high confidence
        final_result.is_attack = true;
        final_result.attack_type = rule_result.primary_attack;
        final_result.confidence = fusion_weights.rule_weight * rule_result.overall_confidence + ...
                                 fusion_weights.ai_weight * ai_result.confidence;
        final_result.fusion_method = 'CONSENSUS';
        
    elseif rule_attack && ~ai_attack
        % Only rules detected
        if rule_result.overall_confidence > 0.8
            final_result.is_attack = true;
            final_result.attack_type = rule_result.primary_attack;
            final_result.confidence = rule_result.overall_confidence * 0.9;
            final_result.fusion_method = 'RULE_ONLY';
        else
            final_result.is_attack = false;
            final_result.attack_type = 'NORMAL';
            final_result.confidence = 0.6;
            final_result.fusion_method = 'RULE_WEAK';
        end
        
    elseif ~rule_attack && ai_attack
        % Only AI detected
        if ai_result.confidence > 0.8
            final_result.is_attack = true;
            final_result.attack_type = ai_result.attack_type;
            final_result.confidence = ai_result.confidence * 0.85;
            final_result.fusion_method = 'AI_ONLY';
        else
            final_result.is_attack = false;
            final_result.attack_type = 'NORMAL';
            final_result.confidence = 0.6;
            final_result.fusion_method = 'AI_WEAK';
        end
        
    else
        % Neither detected attack
        final_result.is_attack = false;
        final_result.attack_type = 'NORMAL';
        final_result.confidence = 0.95;
        final_result.fusion_method = 'BOTH_NORMAL';
    end
    
    % Ensure confidence is in valid range
    final_result.confidence = max(0.1, min(0.99, final_result.confidence));
    
    % Store component results for analysis
    final_result.rule_detection = rule_result;
    final_result.ai_detection = ai_result;
end

function logFeatureData(message, current_time, receiver_node, sender_node)
    % Separate function to log feature data for ALL messages
    global feature_log;
    
    % Extract features using receiver node context
    features = extractMessageFeatures(receiver_node, message, sender_node, current_time);
    
    % Create feature log entry
    log_entry = struct();
    log_entry.message_id = message.id;
    log_entry.timestamp = current_time;
    log_entry.source_id = message.source_id;
    log_entry.destination_id = message.destination_id;
    log_entry.is_attack = message.is_attack;
    
    % Use message's true attack type if available, otherwise fallback to sender node
    if isfield(message, 'true_attack_type') && ~isempty(message.true_attack_type)
        log_entry.attack_type = message.true_attack_type;
    elseif message.is_attack && ~isempty(sender_node) && sender_node.is_attacker
        % Use sender node's attack strategy as the true attack type
        if isfield(sender_node, 'attack_strategy') && ~isempty(sender_node.attack_strategy)
            log_entry.attack_type = sender_node.attack_strategy;
        else
            log_entry.attack_type = 'UNKNOWN_ATTACK';
        end
    else
        log_entry.attack_type = 'NORMAL';
    end
    
    log_entry.features = features; % 43-element feature vector
    if isempty(feature_log)
        feature_log = log_entry;
    else
        feature_log(end+1) = log_entry;
    end
end

function [node, detection_result] = runIDSDetection(node, message, sender_node, current_time)
    start_time = tic;
    
    % Extract features for IDS
    features = extractMessageFeatures(node, message, sender_node, current_time);

    % Log features and label for dataset preparation - MOVED TO SEPARATE FUNCTION
    logFeatureData(message, current_time, node, sender_node);
    
    % NEW: Run both rule-based and AI-based detection
    if node.ids_model.hybrid_mode
        % Rule-based detection
        rule_start = tic;
        rule_result = runRuleBasedDetection(node, message, sender_node, current_time, features);
        rule_time = toc(rule_start);
        
        % AI-based detection
        ai_start = tic;
        [ai_is_attack, ai_attack_type, ai_confidence] = predictAttack(node.ids_model, features);
        ai_time = toc(ai_start);
        
        ai_result = struct();
        ai_result.is_attack = ai_is_attack;
        ai_result.attack_type = ai_attack_type;
        ai_result.confidence = ai_confidence;
        
        % Fusion of results
        fusion_start = tic;
        fused_result = fuseDetectionResults(rule_result, ai_result, node.ids_model.fusion_weights);
        fusion_time = toc(fusion_start);
        
        % Use fused results
        is_attack = fused_result.is_attack;
        attack_type = fused_result.attack_type;
        confidence = fused_result.confidence;
        
        % Additional timing information
        processing_time = toc(start_time) * 1000;
        
        fprintf('HYBRID DETECTION: Rule=%.2fms, AI=%.2fms, Fusion=%.2fms, Method=%s\n', ...
            rule_time*1000, ai_time*1000, fusion_time*1000, fused_result.fusion_method);
    else
        % Original AI-only detection
        [is_attack, attack_type, confidence] = predictAttack(node.ids_model, features);
        processing_time = toc(start_time) * 1000;
    end
    
    detection_result = struct();
    detection_result.message_id = message.id;
    detection_result.is_attack = is_attack;
    detection_result.attack_type = attack_type;
    detection_result.confidence = confidence;
    detection_result.threat_level = assessThreatLevel(attack_type, confidence);
    detection_result.processing_time_ms = processing_time;
    detection_result.detector_id = node.id;
    detection_result.timestamp = current_time;
    
    % NEW: Add hybrid-specific information
    if node.ids_model.hybrid_mode && exist('fused_result', 'var')
        detection_result.fusion_method = fused_result.fusion_method;
        detection_result.rule_triggered = ~isempty(rule_result.triggered_rules);
        detection_result.triggered_rules = rule_result.triggered_rules;
        detection_result.rule_confidence = rule_result.overall_confidence;
        detection_result.ai_confidence = ai_result.confidence;
    end
    
    % Process detection result
    node = processDetectionResult(node, detection_result, message);
    
    % Add to global detection log
    global simulation_data;
    if isempty(simulation_data.detections)
        simulation_data.detections = detection_result;
    else
        simulation_data.detections(end+1) = detection_result;
    end

    if detection_result.is_attack && detection_result.confidence > 0.7
        message.blocked = true;
        message.block_reason = detection_result.attack_type;
        fprintf('Node %d BLOCKED message %s (reason: %s, confidence: %.2f)\n', ...
            node.id, message.id, detection_result.attack_type, detection_result.confidence);
        return;
    end
end

function features = extractMessageFeatures(node, message, sender_node, current_time)
    % Extract comprehensive features for IDS detection
    features = zeros(1, 43); % Matching the Python models feature count
    
    % Determine attack type for fingerprint enhancement
    is_attack = message.is_attack;
    attack_type = 'NORMAL';
    if is_attack && isfield(message, 'true_attack_type')
        attack_type = message.true_attack_type;
    elseif is_attack && ~isempty(sender_node) && sender_node.is_attacker
        attack_type = sender_node.attack_strategy;
    end
    
    % Network topology features (with attack-specific adjustments)
    base_density = length(node.neighbors) / 10;
    features(1) = enhanceFeatureByAttackType(base_density, attack_type, 'node_density');
    features(2) = calculateIsolationFactor(node); % isolation_factor
    features(3) = getEmergencyPriority(message); % emergency_priority
    
    % Hop reliability - Black Hole attacks should show degraded reliability
    base_hop_reliability = calculateHopReliability(message);
    if strcmp(attack_type, 'BLACK_HOLE')
        features(4) = base_hop_reliability * (0.3 + 0.2 * rand()); % 30-50% reliability
    else
        features(4) = base_hop_reliability + 0.05 * randn(); % Add small noise
    end
    
    features(5) = 0.2 + 0.1 * randn(); % network_fragmentation with noise
    features(6) = min(1, length(node.neighbors) / 10); % critical_node_count (normalized by expected max neighbors)
    
    % Black Hole attacks should show reduced backup route availability
    if strcmp(attack_type, 'BLACK_HOLE')
        features(7) = 0.1 + 0.2 * rand(); % 10-30% availability
    else
        features(7) = 0.7 + 0.2 * randn(); % normal with noise
    end
    
    % Message content analysis - Enhanced for attack fingerprints
    base_msg_length = min(1, length(message.content) / 2000);
    features(8) = enhanceFeatureByAttackType(base_msg_length, attack_type, 'message_length');
    
    % Entropy - Spoofing should have higher entropy
    base_entropy = calculateEntropy(message.content);
    if strcmp(attack_type, 'SPOOFING')
        features(9) = min(1, base_entropy + 0.1 + 0.1 * rand()); % Higher entropy
    else
        features(9) = base_entropy + 0.02 * randn(); % Small noise
    end
    
    % Special character ratio - Spoofing should be higher
    base_special_char = calculateSpecialCharRatio(message.content);
    if strcmp(attack_type, 'SPOOFING')
        features(10) = min(1, base_special_char + 0.1 + 0.05 * rand());
    else
        features(10) = base_special_char + 0.01 * randn();
    end
    
    features(11) = calculateNumericRatio(message.content) + 0.01 * randn(); % numeric_ratio with noise
    
    % Emergency keywords - enhanced for spoofing
    base_emergency = countEmergencyKeywords(message.content);
    if strcmp(attack_type, 'SPOOFING')
        features(12) = min(1, base_emergency + 0.1 + 0.1 * rand());
    else
        features(12) = base_emergency + 0.02 * randn();
    end
    
    % Suspicious URLs - much higher for spoofing
    base_urls = countSuspiciousURLs(message.content);
    if strcmp(attack_type, 'SPOOFING')
        features(13) = min(3, base_urls + 1 + randi(2)); % Add 1-3 more suspicious elements
    else
        features(13) = base_urls;
    end
    
    features(14) = countCommandPatterns(message.content); % command_pattern_count
    
    % Traffic pattern analysis - Enhanced for attack signatures
    base_msg_freq = calculateMessageFrequency(node, current_time);
    if strcmp(attack_type, 'FLOODING') || strcmp(attack_type, 'ADAPTIVE_FLOODING')
        features(15) = min(1, base_msg_freq * (2 + rand())); % 2-3x higher frequency
        features(16) = 0.7 + 0.2 * rand(); % High burst_intensity
        features(17) = 0.6 + 0.3 * rand(); % High inter_arrival_variance  
        features(18) = 0.2 + 0.3 * rand(); % Low size_consistency
        features(19) = 0.2 + 0.3 * rand(); % Low timing_regularity
        features(20) = 0.6 + 0.3 * rand(); % High volume_anomaly_score
    else
        features(15) = base_msg_freq + 0.05 * randn(); % Normal with noise
        features(16) = 0.3 + 0.15 * randn(); % burst_intensity with noise
        features(17) = 0.2 + 0.1 * randn(); % inter_arrival_variance with noise
        features(18) = 0.8 + 0.1 * randn(); % size_consistency with noise
        features(19) = 0.7 + 0.1 * randn(); % timing_regularity with noise
        features(20) = 0.1 + 0.05 * randn(); % volume_anomaly_score with noise
    end
    
    % Behavioral fingerprinting - with noise for realism
    features(21) = getSenderReputation(node, message.source_id) + 0.05 * randn(); % sender_reputation
    features(22) = 0.4 + 0.2 * randn(); % message_similarity_score with noise
    features(23) = 0.7 + 0.1 * randn(); % response_pattern with noise
    features(24) = 0.6 + 0.15 * randn(); % interaction_diversity with noise
    features(25) = 0.8 + 0.1 * randn(); % temporal_consistency with noise
    features(26) = 0.9 + 0.05 * randn(); % language_consistency with noise
    
    % Protocol-level features - Enhanced for spoofing detection
    features(27) = calculateTTLAnomaly(message) + 0.02 * randn(); % ttl_anomaly with noise
    features(28) = 0.05 + 0.03 * randn(); % sequence_gap_score with noise
    
    % Routing anomaly - higher for Black Hole attacks
    if strcmp(attack_type, 'BLACK_HOLE')
        features(29) = 0.4 + 0.3 * rand(); % High routing anomaly
    else
        features(29) = 0.1 + 0.05 * randn(); % Normal with noise
    end
    
    % Header integrity - lower for spoofing
    if strcmp(attack_type, 'SPOOFING')
        features(30) = 0.6 + 0.2 * rand(); % Degraded integrity
    else
        features(30) = 0.95 + 0.02 * randn(); % High integrity with noise
    end
    
    features(31) = 0.9 + 0.05 * randn(); % encryption_consistency with noise
    
    % Protocol compliance - lower for spoofing
    if strcmp(attack_type, 'SPOOFING')
        features(32) = 0.5 + 0.3 * rand(); % Poor compliance
    else
        features(32) = 0.95 + 0.02 * randn(); % Good compliance with noise
    end
    
    % Resource and context awareness - Enhanced for Resource Exhaustion
    base_battery_impact = 1 - node.battery_level;
    if strcmp(attack_type, 'RESOURCE_EXHAUSTION')
        features(33) = min(1, base_battery_impact * (2 + rand())); % High battery impact
    else
        features(33) = base_battery_impact + 0.05 * randn(); % Normal with noise
    end
    
    base_processing_load = calculateProcessingLoad(node);
    if strcmp(attack_type, 'RESOURCE_EXHAUSTION')
        features(34) = min(1, base_processing_load * (1.5 + 0.5 * rand())); % High processing load
    else
        features(34) = base_processing_load + 0.05 * randn(); % Normal with noise
    end
    
    % Memory footprint - higher for Resource Exhaustion
    if isempty(node.message_buffer)
        base_memory = 0;
    else
        total_bytes = sum(cellfun(@(msg) length(msg.content), node.message_buffer));
        base_memory = min(1, total_bytes / node.max_buffer_bytes);
    end
    
    if strcmp(attack_type, 'RESOURCE_EXHAUSTION')
        features(35) = min(1, base_memory + 0.3 + 0.2 * rand()); % High memory usage
    else
        features(35) = base_memory + 0.05 * randn(); % Normal with noise
    end
    
    features(36) = calculateSignalStrength(node, sender_node) + 0.05 * randn(); % signal_strength_factor with noise
    % Mobility pattern: normalized cumulative distance moved (with noise)
    if isfield(node, 'total_distance_moved')
        features(37) = min(1, node.total_distance_moved / 200) + 0.02 * randn(); % normalized with noise
    else
        features(37) = 0.02 * rand(); % Small random value
        node.total_distance_moved = 0; % Initialize if missing
    end
    features(38) = getEmergencyContextScore(message) + 0.05 * randn(); % emergency_context_score with noise
    
    % Multi-hop mesh specific - Enhanced for Black Hole detection
    features(39) = calculateRouteStability(node) + 0.05 * randn(); % route_stability with noise
    
    % Forwarding behavior - Black Hole should show very low values
    if isfield(node, 'forwarded_count') && isfield(node, 'received_count') && node.received_count > 0
        base_fwd_behavior = min(1, node.forwarded_count / node.received_count);
        if strcmp(attack_type, 'BLACK_HOLE')
            features(40) = base_fwd_behavior * (0.1 + 0.1 * rand()); % Very low forwarding
        else
            features(40) = base_fwd_behavior + 0.05 * randn(); % Normal with noise
        end
    else
        if strcmp(attack_type, 'BLACK_HOLE')
            features(40) = 0.05 * rand(); % Very low for black hole
        else
            features(40) = 0.02 * rand(); % Small random for others
        end
    end
    
    features(41) = calculateNeighborTrustScore(node, message.source_id) + 0.05 * randn(); % neighbor_trust_score with noise
    features(42) = calculateMeshConnectivityHealth() + 0.05 * randn(); % mesh_connectivity_health with noise
    
    % Redundancy factor: ratio of neighbor overlap with sender (with noise)
    if ~isempty(sender_node) && isfield(sender_node, 'neighbors') && ~isempty(node.neighbors)
        overlap = intersect(node.neighbors, sender_node.neighbors);
        base_redundancy = min(1, length(overlap) / max(1, length(node.neighbors)));
        features(43) = base_redundancy + 0.05 * randn();
    else
        features(43) = 0.1 * rand(); % Small random value
    end
    
    % Ensure all features are within [0,1] bounds
    features = max(0, min(1, features));

% Helper function to enhance features based on attack type
function enhanced_feature = enhanceFeatureByAttackType(base_value, attack_type, feature_name)
    switch feature_name
        case 'node_density'
            if strcmp(attack_type, 'FLOODING') || strcmp(attack_type, 'ADAPTIVE_FLOODING')
                enhanced_feature = min(1, base_value * (1.2 + 0.3 * rand())); % Higher density
            else
                enhanced_feature = base_value + 0.05 * randn();
            end
        case 'message_length'
            if strcmp(attack_type, 'RESOURCE_EXHAUSTION')
                enhanced_feature = min(1, base_value * (1.5 + 0.5 * rand())); % Larger messages
            elseif strcmp(attack_type, 'FLOODING')
                enhanced_feature = min(1, base_value * (1.3 + 0.4 * rand())); % Moderately larger
            else
                enhanced_feature = base_value + 0.05 * randn();
            end
        otherwise
            enhanced_feature = base_value + 0.05 * randn();
    end
end
% --- Helper for mesh connectivity health ---
function health = calculateMeshConnectivityHealth()
    global simulation_data;
    if ~isfield(simulation_data, 'nodes') || isempty(simulation_data.nodes)
        health = 0.8; % fallback
        return;
    end
    nodes = simulation_data.nodes;
    neighbor_counts = arrayfun(@(x) length(x.neighbors), nodes);
    avg_neighbors = mean(neighbor_counts);
    health = avg_neighbors / max(1, (length(nodes)-1)); % Normalized [0,1]
    health = min(max(health, 0), 1);
end

% --- Helper for neighbor trust score ---
function trust = calculateNeighborTrustScore(node, sender_id)
    if node.reputation_scores.isKey(num2str(sender_id))
        trust = node.reputation_scores(num2str(sender_id));
    else
        trust = 0.8; % Default neutral trust
    end
end

% --- Helper for route stability ---
function stability = calculateRouteStability(node)
    % Simple version: if node has a route_history field, compute stability
    if isfield(node, 'route_history') && ~isempty(node.route_history)
        % Count unique routes for each src-dst pair
        unique_routes = numel(unique(node.route_history));
        total_routes = numel(node.route_history);
        if total_routes == 0
            stability = 1.0;
        else
            stability = 1 - (unique_routes / total_routes); % More unique = less stable
        end
        stability = min(max(stability, 0), 1);
    else
        stability = 0.8; % fallback if no history
    end
end
end

% Export feature log as dataset (call this at the end of your main script)
function exportFeatureDataset()
    global feature_log;
    if isempty(feature_log)
        fprintf('No feature log to export.\n');
        return;
    end
    % Deduplicate feature_log by message_id, keeping only the first occurrence
    [~, unique_idx] = unique({feature_log.message_id}, 'first');
    dedup_log = feature_log(sort(unique_idx));
    % Convert to table for easy export
    feature_table = struct2table(dedup_log);
    % Expand features into separate columns with real feature names ONLY
    features_matrix = vertcat(dedup_log.features);
    feature_names = { ...
        'node_density', 'isolation_factor', 'emergency_priority', 'hop_reliability', 'network_fragmentation', 'critical_node_count', 'backup_route_availability', ...
        'message_length', 'entropy_score', 'special_char_ratio', 'numeric_ratio', 'emergency_keyword_count', 'suspicious_url_count', 'command_pattern_count', ...
        'message_frequency', 'burst_intensity', 'inter_arrival_variance', 'size_consistency', 'timing_regularity', 'volume_anomaly_score', ...
        'sender_reputation', 'message_similarity_score', 'response_pattern', 'interaction_diversity', 'temporal_consistency', 'language_consistency', ...
        'ttl_anomaly', 'sequence_gap_score', 'routing_anomaly', 'header_integrity', 'encryption_consistency', 'protocol_compliance_score', ...
        'battery_impact_score', 'processing_load', 'memory_footprint', 'signal_strength_factor', 'mobility_pattern', 'emergency_context_score', ...
        'route_stability', 'forwarding_behavior', 'neighbor_trust_score', 'mesh_connectivity_health', 'redundancy_factor' ...
    };
    for i = 1:length(feature_names)
        feature_table.(feature_names{i}) = features_matrix(:,i);
    end
    feature_table.features = [];
    
    % Ensure attack_type column is properly formatted as categorical for better CSV export
    if ismember('attack_type', feature_table.Properties.VariableNames)
        feature_table.attack_type = categorical(feature_table.attack_type);
    end
    % Save as CSV
    results_dir = 'training_data';
    if ~exist(results_dir, 'dir')
        mkdir(results_dir);
    end
    timestamp = datestr(now, 'yyyymmdd_HHMMSS');
    csv_filename = fullfile(results_dir, sprintf('feature_dataset_%s.csv', timestamp));
    writetable(feature_table, csv_filename);
    fprintf('Feature dataset exported to: %s\n', csv_filename);
    
    % Balance the dataset and create a balanced version
    balanced_table = balanceDataset(feature_table);
    balanced_filename = fullfile(results_dir, sprintf('balanced_feature_dataset_%s.csv', timestamp));
    writetable(balanced_table, balanced_filename);
    fprintf('Balanced feature dataset exported to: %s\n', balanced_filename);
end

function balanced_table = balanceDataset(feature_table)
    % Balance dataset using undersampling and oversampling techniques
    fprintf('Balancing dataset...\n');
    
    % Get attack type distribution
    attack_types = categories(feature_table.attack_type);
    type_counts = countcats(feature_table.attack_type);
    
    fprintf('Original distribution:\n');
    for i = 1:length(attack_types)
        fprintf('  %s: %d\n', attack_types{i}, type_counts(i));
    end
    
    % Determine target count (use median of current counts)
    target_count = round(median(type_counts));
    target_count = max(target_count, 20); % Minimum 20 samples per class
    
    fprintf('Target count per class: %d\n', target_count);
    
    balanced_data = table();
    
    for i = 1:length(attack_types)
        attack_type = attack_types{i};
        type_data = feature_table(feature_table.attack_type == attack_type, :);
        current_count = height(type_data);
        
        if current_count > target_count
            % Undersample (randomly select target_count samples)
            idx = randperm(current_count, target_count);
            sampled_data = type_data(idx, :);
        elseif current_count < target_count
            % Oversample using SMOTE-like technique
            sampled_data = oversampleData(type_data, target_count);
        else
            sampled_data = type_data;
        end
        
        balanced_data = [balanced_data; sampled_data];
    end
    
    % Shuffle the balanced dataset
    idx = randperm(height(balanced_data));
    balanced_table = balanced_data(idx, :);
    
    fprintf('Balanced distribution:\n');
    balanced_types = categories(balanced_table.attack_type);
    balanced_counts = countcats(balanced_table.attack_type);
    for i = 1:length(balanced_types)
        fprintf('  %s: %d\n', balanced_types{i}, balanced_counts(i));
    end
end

function oversampled_data = oversampleData(data, target_count)
    % Simple SMOTE-like oversampling
    current_count = height(data);
    needed = target_count - current_count;
    
    % Start with original data
    oversampled_data = data;
    
    % Generate synthetic samples
    feature_cols = ~ismember(data.Properties.VariableNames, {'message_id', 'timestamp', 'source_id', 'destination_id', 'is_attack', 'attack_type'});
    feature_data = table2array(data(:, feature_cols));
    
    for i = 1:needed
        % Select two random samples from the minority class
        idx1 = randi(current_count);
        idx2 = randi(current_count);
        
        if idx1 == idx2
            idx2 = mod(idx2, current_count) + 1;
        end
        
        % Create synthetic sample by interpolating between the two samples
        alpha = rand(); % Random interpolation factor
        synthetic_features = alpha * feature_data(idx1, :) + (1 - alpha) * feature_data(idx2, :);
        
        % Add small noise for realism
        noise = 0.02 * randn(size(synthetic_features));
        synthetic_features = synthetic_features + noise;
        
        % Ensure values stay in [0,1] range
        synthetic_features = max(0, min(1, synthetic_features));
        
        % Create new row based on first sample but with synthetic features
        new_row = data(idx1, :);
        new_row.message_id = {sprintf('SYNTH_%06d', i)};
        
        % Replace feature values
        new_row(:, feature_cols) = array2table(synthetic_features);
        
        oversampled_data = [oversampled_data; new_row];
    end
end

%% Feature Calculation Functions
function isolation_factor = calculateIsolationFactor(node)
    if length(node.neighbors) == 0
        isolation_factor = 1.0;
    else
        isolation_factor = max(0, 1 - length(node.neighbors) / 8);
    end
end

function priority = getEmergencyPriority(message)
    emergency_keywords = {'emergency', 'help', 'rescue', 'medical', 'fire', 'disaster'};
    content_lower = lower(message.content);
    priority = 0.3; % base priority
    
    for i = 1:length(emergency_keywords)
        if contains(content_lower, emergency_keywords{i})
            priority = priority + 0.2;
        end
    end
    priority = min(priority, 1.0);
end

function reliability = calculateHopReliability(message)
    % Simulate hop reliability based on hop count and TTL
    if message.hop_count == 0
        reliability = 0.9;
    else
        reliability = 0.9 * (0.95 ^ message.hop_count);
    end
end

function entropy = calculateEntropy(text)
    if isempty(text)
        entropy = 0;
        return;
    end
    
    [unique_chars, ~, idx] = unique(text);
    counts = accumarray(idx, 1);
    probabilities = counts / length(text);
    raw_entropy = -sum(probabilities .* log2(probabilities + eps));
    % Normalize by maximum possible entropy (8 bits for 256 possible characters)
    entropy = min(1, raw_entropy / 8.0);
end

function ratio = calculateSpecialCharRatio(text)
    if isempty(text)
        ratio = 0;
        return;
    end
    
    % Use MATLAB's vectorized operations
    is_letter = isletter(text);
    is_digit = (text >= '0' & text <= '9');
    is_space = (text == ' ');
    
    % Special characters are those that are NOT letters, digits, or spaces
    is_special = ~(is_letter | is_digit | is_space);
    
    ratio = sum(is_special) / length(text);
end

function ratio = calculateNumericRatio(text)
    if isempty(text)
        ratio = 0;
        return;
    end
    
    % Count digits using vectorized comparison
    is_digit = (text >= '0' & text <= '9');
    ratio = sum(is_digit) / length(text);
end

function count = countEmergencyKeywords(text)
    emergency_keywords = {'emergency', 'help', 'rescue', 'urgent', 'sos', 'trapped', ...
                         'injured', 'medical', 'fire', 'flood', 'evacuate', 'shelter', ...
                         'missing', 'found', 'safe', 'danger', 'critical', 'alert', ...
                         'breaking', 'immediate', 'disaster', 'crisis', 'victim', 'survivor'};
    text_lower = lower(text);
    raw_count = 0;
    for i = 1:length(emergency_keywords)
        if contains(text_lower, emergency_keywords{i})
            raw_count = raw_count + 1;
        end
    end
    % Normalize by maximum possible keywords (assume max 5 keywords per message is high)
    count = min(1, raw_count / 5);
end

function count = countSuspiciousURLs(text)
    url_patterns = {'http://', 'https://', 'www.', '.com', '.org'};
    count = 0;
    text_lower = lower(text);
    for i = 1:length(url_patterns)
        if contains(text_lower, url_patterns{i})
            count = count + 1;
        end
    end
    
    % Check for suspicious URL characteristics
    if contains(text_lower, 'click') && count > 0
        count = count + 2;
    end
end

function count = countCommandPatterns(text)
    command_patterns = {'delete', 'drop', 'exec', 'system', 'cmd', 'bash', 'sh'};
    text_lower = lower(text);
    count = 0;
    for i = 1:length(command_patterns)
        if contains(text_lower, command_patterns{i})
            count = count + 1;
        end
    end
end

function freq = calculateMessageFrequency(node, current_time)
    % Calculate message frequency in the last minute, normalized to [0,1]
    recent_messages = 0;
    lookback_time = 60; % seconds
    
    for i = 1:length(node.message_history)
        if current_time - node.message_history{i}.timestamp <= lookback_time
            recent_messages = recent_messages + 1;
        end
    end
    
    messages_per_minute = recent_messages / (lookback_time / 60);
    % Normalize by expected maximum frequency (assume max 30 messages/minute in high traffic)
    freq = min(1, messages_per_minute / 30);
end

function reputation = getSenderReputation(node, sender_id)
    if node.reputation_scores.isKey(num2str(sender_id))
        reputation = node.reputation_scores(num2str(sender_id));
    else
        reputation = 0.8; % Default neutral reputation
        node.reputation_scores(num2str(sender_id)) = reputation;
    end
end

function anomaly = calculateTTLAnomaly(message)
    expected_ttl = 10 - message.hop_count;
    if expected_ttl <= 0
        anomaly = 1.0;
    else
        anomaly = abs(message.ttl - expected_ttl) / expected_ttl;
    end
    anomaly = min(anomaly, 1.0);
end

function load = calculateProcessingLoad(node)
    % Improved: processing load based on total message size in buffer
    if isempty(node.message_buffer)
        load = 0;
        return;
    end
    total_bytes = sum(cellfun(@(msg) length(msg.content), node.message_buffer));
    % Assume node.processing_power is in bytes/sec (simulate 1000 bytes/sec typical)
    if ~isfield(node, 'processing_power') || isempty(node.processing_power)
        node.processing_power = 1.0; % fallback
    end
    % Processing load is ratio of buffer size to processing capacity (10 sec window)
    load = (1 - node.processing_power) * 0.5 + (total_bytes / (1000 * 10)) * 0.5;
    load = min(load, 1.0);
end

function strength = calculateSignalStrength(node, sender_node)
    if isempty(sender_node)
        strength = 0.7; % Default
        return;
    end
    
    distance = norm(node.position - sender_node.position);
    max_distance = 50; % transmission range
    strength = max(0.1, 1 - (distance / max_distance));
end

function score = getEmergencyContextScore(message)
    score = getEmergencyPriority(message);
    
    % Adjust based on message type
    if strcmp(message.type, 'EMERGENCY')
        score = score + 0.2;
    elseif strcmp(message.type, 'ATTACK')
        score = score - 0.5;
    end
    
    score = max(0, min(score, 1.0));
end

function [is_attack, attack_type, confidence] = predictAttack(ids_model, features)
    if ids_model.model_loaded
        try
            % Predict using Random Forest
            [prediction, scores] = predict(ids_model.rf_model, features);
            attack_type = prediction{1}; % TreeBagger returns cell array
            
            % Calculate confidence from voting scores
            confidence = max(scores);
            is_attack = ~strcmp(attack_type, 'NORMAL');
            
        catch
            % Fallback to simulation model
            [is_attack, attack_type, confidence] = simulateDetection(ids_model, features);
        end
    else
        % Use simplified simulation model
        [is_attack, attack_type, confidence] = simulateDetection(ids_model, features);
    end
end


function [X, y] = generateTrainingData(n_samples, attack_types)
    % Class distribution matching your Python model
    class_probs = [0.60, 0.12, 0.10, 0.08, 0.05, 0.03, 0.02];
    
    X = [];
    y = {};
    
    for i = 1:n_samples
        % Select class based on distribution
        rand_val = rand();
        cumsum_probs = cumsum(class_probs);
        class_idx = find(rand_val <= cumsum_probs, 1);
        selected_class = attack_types{class_idx};
        
        % Generate features based on class (simplified version)
        features = generateFeaturesForClass(selected_class);
        
        X = [X; features];
        y{end+1} = selected_class;
    end
end

function features = generateFeaturesForClass(class_name)
    % Generate 43 features based on class type
    features = rand(1, 43); % Start with random baseline
    
    switch class_name
        case 'FLOODING'
            features(15) = rand()*100 + 50;     % High message_frequency
            features(21) = rand()*0.2;          % Low sender_reputation
            features(33) = rand()*0.2 + 0.8;    % High battery_impact
        case 'SPOOFING'
            features(13) = randi([1, 5]);       % suspicious_url_count
            features(21) = rand()*0.4;          % Low sender_reputation
            features(10) = rand()*0.5 + 0.3;    % High special_char_ratio
        case 'RESOURCE_EXHAUSTION'
            features(33) = rand()*0.2 + 0.8;    % High battery_impact
            features(8) = rand()*500 + 300;     % Large message size
        % Add other cases as needed
    end
end

function [is_attack, attack_type, confidence] = simulateDetection(ids_model, features)
    % Simplified detection logic for simulation
    
    % Normalize features
    features_norm = features / max(abs(features) + eps);
    
    % Calculate risk score using weighted features
    risk_score = sum(features_norm .* ids_model.feature_weights');
    risk_score = 1 / (1 + exp(-risk_score)); % Sigmoid activation
    
    % Determine if it's an attack based on specific feature patterns
    is_attack = false;
    attack_type = 'NORMAL';
    confidence = 0.5;
    
    % Flooding detection (high message frequency + large size)
    if features(15) > 5 && features(8) > 500
        is_attack = true;
        attack_type = 'FLOODING';
        confidence = 0.8 + 0.15 * rand();
    % Spoofing detection (suspicious URLs + low reputation)
    elseif features(13) > 0 && features(21) < 0.5
        is_attack = true;
        attack_type = 'SPOOFING';
        confidence = 0.7 + 0.2 * rand();
    % Resource exhaustion detection (high battery impact + large messages)
    elseif features(33) > 0.8 && features(8) > 300
        is_attack = true;
        attack_type = 'RESOURCE_EXHAUSTION';
        confidence = 0.6 + 0.25 * rand();
    end
    
    % Add some noise to make it realistic
    confidence = min(0.99, max(0.1, confidence + 0.05 * randn()));
end

function threat_level = assessThreatLevel(attack_type, confidence)
    if strcmp(attack_type, 'NORMAL')
        threat_level = 0; % NONE
    elseif confidence < 0.5
        threat_level = 1; % LOW
    elseif (strcmp(attack_type, 'SPOOFING') || strcmp(attack_type, 'FLOODING')) && confidence > 0.7
        threat_level = 3; % HIGH
    elseif strcmp(attack_type, 'RESOURCE_EXHAUSTION') && confidence > 0.6
        threat_level = 2; % MEDIUM
    else
        threat_level = 2; % MEDIUM
    end
end

function node = processDetectionResult(node, detection_result, original_message)
    % Update detection statistics
    if original_message.is_attack
        if detection_result.is_attack
            node.detection_stats.tp = node.detection_stats.tp + 1; % True Positive
        else
            node.detection_stats.fn = node.detection_stats.fn + 1; % False Negative
        end
    else
        if detection_result.is_attack
            node.detection_stats.fp = node.detection_stats.fp + 1; % False Positive
        else
            node.detection_stats.tn = node.detection_stats.tn + 1; % True Negative
        end
    end
    
    % Update sender reputation
    sender_id = num2str(original_message.source_id);
    current_reputation = getSenderReputation(node, original_message.source_id);
    
    if detection_result.is_attack && detection_result.confidence > 0.7
        new_reputation = current_reputation * 0.8; % Decrease reputation
    elseif ~detection_result.is_attack
        new_reputation = min(1.0, current_reputation + 0.01); % Slightly increase reputation
    else
        new_reputation = current_reputation;
    end
    
    node.reputation_scores(sender_id) = new_reputation;
    
    % Log significant detections
    if detection_result.is_attack && detection_result.confidence > 0.6
        fprintf('Node %d detected attack: %s (confidence: %.2f) from message %s\n', ...
            node.id, detection_result.attack_type, detection_result.confidence, detection_result.message_id);
        % Log the detected attack
        logMessageDetails(original_message, detection_result, node, detection_result.timestamp);
    end
end

%% Attacker Functions
function [node, attack_message] = launchAttack(node, current_time, target_nodes)
    attack_message = []; % Initialize return value
    
    if current_time - node.last_attack_time < node.attack_frequency
        return;
    end
    
    node.last_attack_time = current_time;
    
    % Select random target
    if ~isempty(target_nodes)
        target_id = target_nodes(randi(length(target_nodes)));
    else
        target_id = randi(15); % Random normal node
    end
    
    % Generate attack message based on strategy
    attack_content = generateAdvancedAttackContent(node);
    
    fprintf('ATTACKER Node %d launching %s attack at time %.2f\n', ...
        node.id, node.attack_strategy, current_time);
    
    % Send attack message and capture the returned message
    [node, attack_message] = sendMessage(node, attack_content, 'ATTACK', target_id, current_time);
end

function content = generateAdvancedAttackContent(node)
    if ~node.is_attacker || isempty(node.attack_strategy)
        content = generateNormalMessage();
        return;
    end

    switch node.attack_strategy
        case 'FLOODING'
            content = generateFloodingContent(node);
        case 'ADAPTIVE_FLOODING'
            content = generateAdaptiveFloodingContent(node);
        case 'RESOURCE_EXHAUSTION'
            content = generateResourceExhaustionContent(node);
        case 'BLACK_HOLE'
            content = ''; % Black hole does not generate content
        case 'SPOOFING'
            content = generateSpoofingContent(node);
        otherwise
            content = generateNormalMessage();
    end
function content = generateFloodingContent(node)
    % Enhanced flooding: varied message patterns to increase entropy and size variation
    base_patterns = {
        'FLOOD ALERT: WATER LEVELS RISING RAPIDLY! ',
        'EMERGENCY BROADCAST: EVACUATE IMMEDIATELY! ',
        'CRITICAL WARNING: INFRASTRUCTURE FAILURE! ',
        'URGENT UPDATE: DISASTER ZONE EXPANDING! '
    };
    selected_pattern = base_patterns{randi(length(base_patterns))};
    
    % Variable repetition with noise characters to increase entropy
    repeat_count = 20 + randi(30); % 20-50 repetitions
    noise_chars = '!@#$%^&*()_+-=[]{}|;:,.<>?';
    
    content = '';
    for i = 1:repeat_count
        content = [content, selected_pattern];
        if rand() < 0.3 % 30% chance to add noise
            content = [content, noise_chars(randi(length(noise_chars)))];
        end
    end
end


function content = generateAdaptiveFloodingContent(node)
    % Adaptive flooding: send a burst of messages with variable size and timing
    base_msg = 'ADAPTIVE FLOOD ALERT: WATER LEVELS RISING! ';
    burst_size = 10 + randi(10); % Adaptive burst size
    if isfield(node, 'attack_params') && isfield(node.attack_params, 'message_burst_size')
        burst_size = node.attack_params.message_burst_size;
    end
    content = repmat(base_msg, 1, burst_size);
    % Optionally, add some randomization to simulate adaptation
    if rand() > 0.5
        content = [content, sprintf(' [ADAPTIVE BURST at %.2f]', now)];
    end
end

function content = generateResourceExhaustionContent(node)
    % Enhanced resource exhaustion: extremely large messages with varied patterns
    base_msg = 'RESOURCE_EXHAUSTION_ATTACK: ';
    
    if isfield(node, 'attack_params') && isfield(node.attack_params, 'target_resource')
        switch node.attack_params.target_resource
            case 1 % Battery
                payload_base = 'BATTERY_DRAIN_PAYLOAD_';
                payload_multiplier = 300 + randi(200); % 300-500 repetitions
            case 2 % Processing
                payload_base = 'PROCESSING_OVERLOAD_COMPUTATION_';
                payload_multiplier = 200 + randi(150); % 200-350 repetitions
            case 3 % Memory
                payload_base = 'MEMORY_BOMB_ALLOCATION_';
                payload_multiplier = 400 + randi(200); % 400-600 repetitions
            otherwise
                payload_base = 'GENERIC_RESOURCE_DRAIN_';
                payload_multiplier = 250 + randi(100); % 250-350 repetitions
        end
    else
        payload_base = 'GENERIC_RESOURCE_DRAIN_';
        payload_multiplier = 250 + randi(100);
    end
    
    % Create large payload with some entropy
    payload = '';
    for i = 1:payload_multiplier
        payload = [payload, payload_base, sprintf('%04d_', i)];
        if mod(i, 50) == 0 % Add entropy every 50 iterations
            payload = [payload, sprintf('ENTROPY_%s_', dec2hex(randi(65535)))];
        end
    end
    
    content = [base_msg, payload];
end


function content = generateSpoofingContent(node)
    % Enhanced spoofing: more sophisticated with higher entropy and special characters
    spoof_templates = {
        'URGENT: Click http://malicious-site%d.com/rescue?id=%s for emergency instructions!',
        'EMERGENCY UPDATE: Visit www.fake-help%d.org/updates#%s for critical info!',
        'SECURITY ALERT: Verify account at https://phishing%d.com/secure/%s NOW!',
        'RESCUE COORDINATION: Go to www.spoofed-site%d.com/evacuation?token=%s for details!',
        'MEDICAL EMERGENCY: Contact fake-medical%d.org/urgent/%s for immediate help!'
    };
    
    template = spoof_templates{randi(length(spoof_templates))};
    
    % Generate random parameters to increase entropy
    random_num = randi(9999);
    random_token = '';
    chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
    for i = 1:8
        random_token(end+1) = chars(randi(length(chars)));
    end
    
    content = sprintf(template, random_num, random_token);
    
    % Add extra suspicious elements
    if rand() < 0.5
        content = [content, sprintf(' [URGENT_CODE: %d]', randi(99999))];
    end
end
end











function content = generateNormalMessage()
    % Emergency chat messages during disaster scenarios
    message_categories = struct();
    
    % Emergency Coordination (High Priority/Frequency)
    message_categories.emergency_coordination = {
        'Family group: Everyone check in! Are you all safe?',
        'Dad: I''m okay, stuck at office building but safe',
        'Mom: Kids and I are at community center shelter',
        'Sarah: Can''t reach grandma, anyone near Elm Street?',
        'Mike: Roads flooded on Highway 9, find alternate route',
        'Emergency: Medical help needed at Johnson house!',
        'URGENT: Missing person - has anyone seen little Tommy?',
        'Group: Water rising fast, evacuate NOW if you''re in Zone 3',
        'Alert: Power lines down on Main St, stay away!',
        'SOS: Trapped in basement, water coming in, send help!'
    };
    
    % Safety Status Updates (High Frequency)
    message_categories.safety_status = {
        'Status: I''m safe at the school gym shelter',
        'Update: Made it to higher ground, phone battery at 30%',
        'Safe: Reached evacuation center, looking for family',
        'OK: House damaged but we''re all uninjured',
        'Checking in: Staying with neighbors, have food and water',
        'Location: At Red Cross station, getting medical help',
        'Status update: Car stuck but walking to safety',
        'All good: Found shelter in community building',
        'Safe zone: Made it to the hill, can see flooding below',
        'Secure: In emergency bunker with 20 other people'
    };
    
    % Resource Requests (Medium Frequency)
    message_categories.resource_requests = {
        'Need: Running out of water, any nearby distribution points?',
        'Help: Baby formula needed urgently at women''s shelter',
        'Request: Medication for diabetes, pharmacy closed',
        'Food: Anyone have extra supplies for elderly neighbors?',
        'Transport: Need ride to hospital, roads blocked',
        'Shelter: Our house collapsed, where can family of 4 stay?',
        'Generator: Power out for 2 days, need to charge phones',
        'Medical: First aid supplies needed at apartment complex',
        'Fuel: Car almost empty, any gas stations open?',
        'Information: Which roads are still passable?'
    };
    
    % Rescue Coordination (Medium Frequency)
    message_categories.rescue_coordination = {
        'Rescue: Boat available to help evacuate people',
        'Volunteer: Doctor here, can provide medical assistance',
        'Help offered: Have chainsaw, can clear fallen trees',
        'Transport: Van with space for 8 people to evacuation center',
        'Supplies: Distributing water bottles at park entrance',
        'Communication: Setting up charging station for phones',
        'Search: Organizing search party for missing residents',
        'Coordination: Meeting at fire station to plan rescue ops',
        'Skills: Electrician available for emergency repairs',
        'Equipment: Have rope and tools for rescue operations'
    };
    
    % Information Sharing (Low Frequency)
    message_categories.information_sharing = {
        'Info: Evacuation buses running every 30 minutes',
        'Update: Airport closed, all flights cancelled',
        'News: Emergency shelters now open at all schools',
        'Weather: Storm expected to pass by midnight',
        'Roads: Bridge on Sunset Ave is still safe to cross',
        'Services: Hospital emergency room still operational',
        'Warning: Avoid downtown area, buildings unstable',
        'Notice: Curfew in effect from 8pm to 6am',
        'Alert: Boil water advisory for entire district',
        'Broadcast: Government aid arriving tomorrow morning'
    };
    
    % Select category based on disaster communication patterns
    categories = fieldnames(message_categories);
    category_weights = [0.30, 0.25, 0.20, 0.15, 0.10]; % Emergency coordination most frequent
    
    rand_val = rand();
    cumsum_weights = cumsum(category_weights);
    category_idx = find(rand_val <= cumsum_weights, 1);
    selected_category = categories{category_idx};
    
    messages = message_categories.(selected_category);
    content = messages{randi(length(messages))};
end
function message_id = generateMessageID()
    persistent counter;
    if isempty(counter)
        counter = 1;
    else
        counter = counter + 1;
    end
    message_id = sprintf('MSG_%06d', counter);
end

%% Visualization Functions
function visualizeNetwork(nodes, current_time)
    figure(1);
    clf;
    hold on;
    
    % Plot normal nodes
    for i = 1:length(nodes)
        if ~nodes(i).is_attacker
            scatter(nodes(i).position(1), nodes(i).position(2), 100, 'b', 'filled');
            text(nodes(i).position(1)+5, nodes(i).position(2)+5, sprintf('N%d', nodes(i).id), ...
                'FontSize', 8, 'Color', 'blue');
        end
    end
    
    % Plot attacker nodes
    for i = 1:length(nodes)
        if nodes(i).is_attacker
            scatter(nodes(i).position(1), nodes(i).position(2), 120, 'r', 'filled', 's');
            text(nodes(i).position(1)+5, nodes(i).position(2)+5, sprintf('A%d', nodes(i).id), ...
                'FontSize', 8, 'Color', 'red', 'FontWeight', 'bold');
        end
    end
    
    % Draw connections
    for i = 1:length(nodes)
        for j = 1:length(nodes(i).neighbors)
            neighbor_id = nodes(i).neighbors(j);
            neighbor_idx = find([nodes.id] == neighbor_id);
            if ~isempty(neighbor_idx)
                plot([nodes(i).position(1), nodes(neighbor_idx).position(1)], ...
                     [nodes(i).position(2), nodes(neighbor_idx).position(2)], ...
                     'k--', 'LineWidth', 0.5, 'Color', [0.7 0.7 0.7]);
            end
        end
    end
    
    xlim([0 200]);
    ylim([0 200]);
    grid on;
    title(sprintf('Bluetooth Mesh Network at Time: %.1f seconds', current_time));
    xlabel('X Position (meters)');
    ylabel('Y Position (meters)');
    legend({'Normal Nodes', 'Attacker Nodes'}, 'Location', 'best');
    hold off;
    drawnow;
end

function updateStatistics(current_time)
    global simulation_data;
    
    % Calculate statistics for the last 10 minutes
    time_window = 600; % 10 minutes
    start_time = max(0, current_time - time_window);
    
    % Filter messages and detections within time window, robust to missing timestamp fields
    messages = simulation_data.messages;
    if isempty(messages)
        recent_messages = messages;
    else
        has_timestamp = arrayfun(@(m) isfield(m, 'timestamp'), messages);
        messages_with_time = messages(has_timestamp);
        recent_messages = messages_with_time([messages_with_time.timestamp] >= start_time);
    end
    detections = simulation_data.detections;
    if isempty(detections)
        recent_detections = detections;
    else
        has_timestamp = arrayfun(@(d) isfield(d, 'timestamp'), detections);
        detections_with_time = detections(has_timestamp);
        recent_detections = detections_with_time([detections_with_time.timestamp] >= start_time);
    end
    
    % Calculate statistics
    stats = struct();
    stats.current_time = current_time;
    stats.total_messages = length(recent_messages);
    % Only include messages with is_attack field
    if isempty(recent_messages)
        stats.attack_messages = 0;
        stats.normal_messages = 0;
    else
        has_is_attack = arrayfun(@(m) isfield(m, 'is_attack'), recent_messages);
        messages_with_attack = recent_messages(has_is_attack);
        stats.attack_messages = sum([messages_with_attack.is_attack]);
        stats.normal_messages = length(messages_with_attack) - stats.attack_messages;
    end
    stats.total_detections = length(recent_detections);
    % Only include detections with is_attack field
    if isempty(recent_detections)
        stats.attacks_detected = 0;
    else
        has_is_attack_det = arrayfun(@(d) isfield(d, 'is_attack'), recent_detections);
        detections_with_attack = recent_detections(has_is_attack_det);
        stats.attacks_detected = sum([detections_with_attack.is_attack]);
    end
    stats.detection_rate = stats.attacks_detected / max(stats.attack_messages, 1);
    
    % Calculate per-attack-type statistics
    attack_types = {'FLOODING', 'ADAPTIVE_FLOODING', 'BLACK_HOLE', 'SPOOFING', 'RESOURCE_EXHAUSTION'};
    for i = 1:length(attack_types)
        if isempty(recent_detections)
            stats.(sprintf('%s_detected', lower(attack_types{i}))) = 0;
        else
            has_attack_type = arrayfun(@(d) isfield(d, 'attack_type'), recent_detections);
            detections_with_type = recent_detections(has_attack_type);
            if isempty(detections_with_type)
                stats.(sprintf('%s_detected', lower(attack_types{i}))) = 0;
            else
                type_detections = detections_with_type(strcmp({detections_with_type.attack_type}, attack_types{i}));
                stats.(sprintf('%s_detected', lower(attack_types{i}))) = length(type_detections);
            end
        end
    end
    
    % Calculate average confidence and processing time
    if ~isempty(recent_detections)
        stats.avg_confidence = mean([recent_detections.confidence]);
        stats.avg_processing_time = mean([recent_detections.processing_time_ms]);
    else
        stats.avg_confidence = 0;
        stats.avg_processing_time = 0;
    end
    
    simulation_data.statistics = stats;
end

function displayStatistics(stats)
    fprintf('\n=== NETWORK STATISTICS (Last 10 minutes) ===\n');
    fprintf('Current Simulation Time: %.1f seconds (%.1f minutes)\n', stats.current_time, stats.current_time/60);
    fprintf('Total Messages: %d\n', stats.total_messages);
    fprintf('Normal Messages: %d\n', stats.normal_messages);
    fprintf('Attack Messages: %d\n', stats.attack_messages);
    fprintf('Total Detections: %d\n', stats.total_detections);
    fprintf('Attacks Detected: %d\n', stats.attacks_detected);
    fprintf('Detection Rate: %.2f%%\n', stats.detection_rate * 100);
    
    if stats.avg_confidence > 0
        fprintf('Average Detection Confidence: %.3f\n', stats.avg_confidence);
        fprintf('Average Processing Time: %.2f ms\n', stats.avg_processing_time);
    end
    
    fprintf('\n--- Attack Type Breakdown ---\n');
    attack_types = {'flooding', 'adaptive_flooding', 'black_hole', 'spoofing', 'resource_exhaustion'};
    for i = 1:length(attack_types)
        field_name = sprintf('%s_detected', attack_types{i});
        if isfield(stats, field_name)
            fprintf('%s: %d detections\n', upper(attack_types{i}), stats.(field_name));
        end
    end
    fprintf('===========================================\n\n');
end

function plotRealTimeStatistics(stats_history)
    if length(stats_history) < 2
        return;
    end
    
    figure(2);
    
    % Extract time series data
    times = [stats_history.current_time] / 60; % Convert to minutes
    total_messages = [stats_history.total_messages];
    attack_messages = [stats_history.attack_messages];
    attacks_detected = [stats_history.attacks_detected];
    detection_rates = [stats_history.detection_rate] * 100;
    
    % Create subplots
    subplot(2, 2, 1);
    plot(times, total_messages, 'b-', 'LineWidth', 2);
    hold on;
    plot(times, attack_messages, 'r-', 'LineWidth', 2);
    xlabel('Time (minutes)');
    ylabel('Message Count');
    title('Message Traffic Over Time');
    legend('Total Messages', 'Attack Messages', 'Location', 'best');
    grid on;
    
    subplot(2, 2, 2);
    plot(times, attacks_detected, 'g-', 'LineWidth', 2);
    xlabel('Time (minutes)');
    ylabel('Attacks Detected');
    title('IDS Detection Performance');
    grid on;
    
    subplot(2, 2, 3);
    plot(times, detection_rates, 'm-', 'LineWidth', 2);
    xlabel('Time (minutes)');
    ylabel('Detection Rate (%)');
    title('Detection Rate Over Time');
    ylim([0 100]);
    grid on;
    
    % Battery levels simulation
    subplot(2, 2, 4);
    battery_sim = max(10, 90 - times * 2); % 2% per minute depletion, min 10%
    plot(times, battery_sim, 'color', [1 0.5 0], 'LineWidth', 2);
    ylim([0 100]);
    ylabel('Average Battery Level (%)');
    xlabel('Time (minutes)');
    title('Network Resource Status');
    grid on;
    
    sgtitle('Real-time Network Monitoring Dashboard');
    drawnow;
end

function generateComprehensiveReport(nodes, stats_history)
    global simulation_data NUM_NORMAL_NODES NUM_ATTACK_NODES SIMULATION_TIME MESSAGE_INTERVAL AREA_SIZE;
    
    fprintf('\n\n');
    fprintf('################################################################\n');
    fprintf('#                COMPREHENSIVE SIMULATION REPORT              #\n');
    fprintf('################################################################\n\n');
    
    % Overall simulation summary
    if ~isempty(stats_history)
        final_stats = stats_history(end);
        fprintf('=== SIMULATION OVERVIEW ===\n');
        fprintf('Total Simulation Time: %.1f minutes\n', final_stats.current_time/60);
        fprintf('Network Size: %d nodes (%d normal, %d attackers)\n', ...
            length(nodes), sum(~[nodes.is_attacker]), sum([nodes.is_attacker]));
        fprintf('Message Transmission Interval: %d seconds\n', MESSAGE_INTERVAL);
        fprintf('Total Messages Generated: %d\n', length(simulation_data.messages));
        fprintf('Total IDS Detections: %d\n', length(simulation_data.detections));
    end
    
    % Network topology analysis
    fprintf('\n=== NETWORK TOPOLOGY ANALYSIS ===\n');
    neighbor_counts = arrayfun(@(x) length(x.neighbors), nodes);
    avg_neighbors = mean(neighbor_counts);
    max_neighbors = max(neighbor_counts);
    min_neighbors = min(neighbor_counts);
    
    fprintf('Average Neighbors per Node: %.2f\n', avg_neighbors);
    fprintf('Maximum Neighbors: %d\n', max_neighbors);
    fprintf('Minimum Neighbors: %d\n', min_neighbors);
    fprintf('Network Connectivity: %.2f%%\n', (avg_neighbors / (length(nodes)-1)) * 100);
    
    % IDS Performance Analysis
    fprintf('\n=== IDS PERFORMANCE ANALYSIS ===\n');
    
    % Calculate overall performance metrics
    normal_nodes = nodes(~[nodes.is_attacker]);
    total_tp = sum(arrayfun(@(x) x.detection_stats.tp, normal_nodes));
    total_fp = sum(arrayfun(@(x) x.detection_stats.fp, normal_nodes));
    total_tn = sum(arrayfun(@(x) x.detection_stats.tn, normal_nodes));
    total_fn = sum(arrayfun(@(x) x.detection_stats.fn, normal_nodes));
    
    if (total_tp + total_fp + total_tn + total_fn) > 0
        accuracy = (total_tp + total_tn) / (total_tp + total_fp + total_tn + total_fn);
        precision = total_tp / max(total_tp + total_fp, 1);
        recall = total_tp / max(total_tp + total_fn, 1);
        f1_score = 2 * (precision * recall) / max(precision + recall, eps);
        fpr = total_fp / max(total_fp + total_tn, 1);
        
        fprintf('Overall IDS Accuracy: %.3f (%.1f%%)\n', accuracy, accuracy*100);
        fprintf('Precision: %.3f\n', precision);
        fprintf('Recall (Detection Rate): %.3f\n', recall);
        fprintf('F1-Score: %.3f\n', f1_score);
        fprintf('False Positive Rate: %.3f\n', fpr);
    end
    
    fprintf('\nConfusion Matrix:\n');
    fprintf('                 Predicted\n');
    fprintf('                Normal  Attack\n');
    fprintf('Actual Normal   %4d    %4d\n', total_tn, total_fp);
    fprintf('Actual Attack   %4d    %4d\n', total_fn, total_tp);
    
    % Per-node analysis
    fprintf('\n=== PER-NODE ANALYSIS ===\n');
    fprintf('Node ID | Type    | Neighbors | Battery | TP | FP | TN | FN | Accuracy\n');
    fprintf('--------|---------|-----------|---------|----|----|----|----|----------\n');
    
    for i = 1:length(nodes)
        node = nodes(i);
        if ~node.is_attacker
            node_total = node.detection_stats.tp + node.detection_stats.fp + ...
                        node.detection_stats.tn + node.detection_stats.fn;
            if node_total > 0
                node_accuracy = (node.detection_stats.tp + node.detection_stats.tn) / node_total;
            else
                node_accuracy = 0;
            end
            
            fprintf('%7d | Normal  | %9d | %6.1f%% | %2d | %2d | %2d | %2d | %7.3f\n', ...
                node.id, length(node.neighbors), node.battery_level*100, ...
                node.detection_stats.tp, node.detection_stats.fp, ...
                node.detection_stats.tn, node.detection_stats.fn, node_accuracy);
        else
            fprintf('%7d | Attack  | %9d | %6.1f%% | -- | -- | -- | -- | -------\n', ...
                node.id, length(node.neighbors), node.battery_level*100);
        end
    end
    
    % Attack analysis
    fprintf('\n=== ATTACK ANALYSIS ===\n');
    attack_messages = simulation_data.messages([simulation_data.messages.is_attack]);
    
    if ~isempty(attack_messages)
        fprintf('Total Attack Messages: %d\n', length(attack_messages));
        
        % Count by attack type (from attacker nodes)
        attacker_nodes = nodes([nodes.is_attacker]);
        for i = 1:length(attacker_nodes)
            fprintf('Attacker Node %d Strategy: %s\n', attacker_nodes(i).id, attacker_nodes(i).attack_strategy);
        end
        
        % Detection success by attack type
        detected_attacks = simulation_data.detections([simulation_data.detections.is_attack]);
        if ~isempty(detected_attacks)
            unique_types = unique({detected_attacks.attack_type});
            fprintf('\nDetection Success by Attack Type:\n');
            for i = 1:length(unique_types)
                type_count = sum(strcmp({detected_attacks.attack_type}, unique_types{i}));
                fprintf('%s: %d detections\n', unique_types{i}, type_count);
            end
        end
    end
    
    % Resource consumption analysis
    fprintf('\n=== RESOURCE CONSUMPTION ANALYSIS ===\n');
    initial_battery = 0.9; % Assumed initial average
    current_batteries = [nodes.battery_level];
    current_avg_battery = mean(current_batteries);
    battery_consumed = (initial_battery - current_avg_battery) * 100;
    
    fprintf('Average Battery Consumption: %.1f%%\n', battery_consumed);
    fprintf('Current Average Battery Level: %.1f%%\n', current_avg_battery * 100);
    fprintf('Lowest Battery Level: %.1f%%\n', min(current_batteries) * 100);
    
    % Calculate average processing times
    if ~isempty(simulation_data.detections)
        processing_times = [simulation_data.detections.processing_time_ms];
        avg_processing_time = mean(processing_times);
        max_processing_time = max(processing_times);
        fprintf('Average IDS Processing Time: %.2f ms\n', avg_processing_time);
        fprintf('Maximum IDS Processing Time: %.2f ms\n', max_processing_time);
    end
    
    % Network efficiency metrics
    fprintf('\n=== NETWORK EFFICIENCY METRICS ===\n');
    if ~isempty(simulation_data.messages)
        hop_counts = [simulation_data.messages.hop_count];
        total_hops = sum(hop_counts);
        avg_hops = total_hops / length(simulation_data.messages);
        fprintf('Average Hop Count per Message: %.2f\n', avg_hops);
        
        % Message delivery success estimation
        ttl_values = [simulation_data.messages.ttl];
        successful_messages = sum(ttl_values > 0);
        delivery_rate = successful_messages / length(simulation_data.messages);
        fprintf('Estimated Message Delivery Rate: %.1f%%\n', delivery_rate * 100);
    end
    
    % Time-based analysis
    if length(stats_history) > 1
        fprintf('\n=== TEMPORAL ANALYSIS ===\n');
        detection_rates = [stats_history.detection_rate];
        avg_detection_rate = mean(detection_rates);
        std_detection_rate = std(detection_rates);
        
        fprintf('Average Detection Rate: %.1f%%\n', avg_detection_rate * 100);
        fprintf('Detection Rate Stability (StdDev): %.3f\n', std_detection_rate);
        
        % Peak analysis
        message_counts = [stats_history.total_messages];
        [max_messages, max_idx] = max(message_counts);
        peak_time = stats_history(max_idx).current_time / 60;
        fprintf('Peak Message Activity: %d messages at %.1f minutes\n', max_messages, peak_time);
    end
    
    % Recommendations
    fprintf('\n=== RECOMMENDATIONS ===\n');
    if total_tp + total_fn > 0
        detection_rate = total_tp / (total_tp + total_fn);
        if detection_rate < 0.8
            fprintf('• Detection rate (%.1f%%) is below 80%%. Consider model retraining.\n', detection_rate*100);
        end
    end
    
    if total_fp / max(total_fp + total_tn, 1) > 0.1
        fprintf('• False positive rate is high. Consider adjusting detection thresholds.\n');
    end
    
    if current_avg_battery < 0.3
        fprintf('• Average battery level is low. Consider power optimization.\n');
    end
    
    if ~isempty(simulation_data.detections)
        avg_proc_time = mean([simulation_data.detections.processing_time_ms]);
        if avg_proc_time > 50
            fprintf('• IDS processing time is high. Consider model optimization.\n');
        end
    end

    fprintf('\n=== HYBRID IDS ANALYSIS ===\n');
    
    % Check if we have hybrid detection data
    if ~isempty(simulation_data.detections) && isfield(simulation_data.detections(1), 'fusion_method')
        
        % Analyze fusion methods used
        fusion_methods = {simulation_data.detections.fusion_method};
        unique_methods = unique(fusion_methods);
        
        fprintf('Fusion Method Distribution:\n');
        for i = 1:length(unique_methods)
            method_count = sum(strcmp(fusion_methods, unique_methods{i}));
            percentage = (method_count / length(fusion_methods)) * 100;
            fprintf('  %s: %d (%.1f%%)\n', unique_methods{i}, method_count, percentage);
        end
        
        % Rule-based vs AI-based detection comparison
        rule_detections = simulation_data.detections([simulation_data.detections.rule_triggered]);
        ai_only_detections = simulation_data.detections(strcmp({simulation_data.detections.fusion_method}, 'AI_ONLY_HIGH_CONF'));
        rule_only_detections = simulation_data.detections(strcmp({simulation_data.detections.fusion_method}, 'RULE_ONLY_HIGH_CONF'));
        
        fprintf('\nDetection Source Analysis:\n');
        fprintf('  Rule-triggered detections: %d\n', length(rule_detections));
        fprintf('  AI-only detections: %d\n', length(ai_only_detections));
        fprintf('  Rule-only detections: %d\n', length(rule_only_detections));
        
        % Average confidence comparison
        if ~isempty(rule_detections)
            avg_rule_conf = mean([rule_detections.rule_confidence]);
            avg_ai_conf = mean([rule_detections.ai_confidence]);
            fprintf('  Average rule confidence: %.3f\n', avg_rule_conf);
            fprintf('  Average AI confidence: %.3f\n', avg_ai_conf);
        end
        
        % Rule trigger analysis
        all_triggered_rules = {};
        for i = 1:length(simulation_data.detections)
            if isfield(simulation_data.detections(i), 'triggered_rules')
                all_triggered_rules = [all_triggered_rules, simulation_data.detections(i).triggered_rules];
            end
        end
        
        if ~isempty(all_triggered_rules)
            unique_rules = unique(all_triggered_rules);
            fprintf('\nMost Triggered Rules:\n');
            for i = 1:length(unique_rules)
                rule_count = sum(strcmp(all_triggered_rules, unique_rules{i}));
                fprintf('  %s: %d times\n', unique_rules{i}, rule_count);
            end
        end
        
    else
        fprintf('No hybrid detection data available.\n');
    end
    
    fprintf('\n################################################################\n');
    fprintf('#                     END OF REPORT                           #\n');
    fprintf('################################################################\n\n');
end

function saveSimulationResults(nodes, stats_history)
    global simulation_data NUM_NORMAL_NODES NUM_ATTACK_NODES SIMULATION_TIME MESSAGE_INTERVAL AREA_SIZE;
    
    % Create results directory
    results_dir = 'simulation_results';
    if ~exist(results_dir, 'dir')
        mkdir(results_dir);
    end
    
    % Generate timestamp for filenames
    timestamp = datestr(now, 'yyyymmdd_HHMMSS');
    
    % Save simulation data
    filename = fullfile(results_dir, sprintf('simulation_data_%s.mat', timestamp));
    save(filename, 'nodes', 'stats_history', 'simulation_data', 'NUM_NORMAL_NODES', ...
         'NUM_ATTACK_NODES', 'SIMULATION_TIME', 'MESSAGE_INTERVAL');
    
    fprintf('Simulation results saved to: %s\n', filename);
    
    % Export statistics to CSV
    if ~isempty(stats_history)
        stats_table = struct2table(stats_history);
        csv_filename = fullfile(results_dir, sprintf('statistics_%s.csv', timestamp));
        writetable(stats_table, csv_filename);
        fprintf('Statistics exported to: %s\n', csv_filename);
    end
    
    % Export detection results to CSV if we have detections
    if ~isempty(simulation_data.detections)
        detections_struct = simulation_data.detections;
        
        % Convert struct array to table
        if length(detections_struct) > 0
            detection_data = struct();
            detection_data.message_id = {detections_struct.message_id}';
            detection_data.is_attack = logical([detections_struct.is_attack]');
            detection_data.attack_type = {detections_struct.attack_type}';
            detection_data.confidence = [detections_struct.confidence]';
            detection_data.threat_level = [detections_struct.threat_level]';
            detection_data.processing_time_ms = [detections_struct.processing_time_ms]';
            detection_data.detector_id = [detections_struct.detector_id]';
            detection_data.timestamp = [detections_struct.timestamp]';
            
            detection_table = struct2table(detection_data);
            detection_csv = fullfile(results_dir, sprintf('detections_%s.csv', timestamp));
            writetable(detection_table, detection_csv);
            fprintf('Detection results exported to: %s\n', detection_csv);
        end
    end
end

function shared_model = createSharedIDSModel()
    shared_model = struct();
    shared_model.model_loaded = false;
    shared_model.attack_types = {'NORMAL', 'FLOODING', 'ADAPTIVE_FLOODING', 'BLACK_HOLE', 'SPOOFING', 'RESOURCE_EXHAUSTION'};
    
    shared_model.feature_weights = rand(43, 1);
    shared_model.rules = createDetectionRules();
    shared_model.hybrid_mode = true;
    shared_model.rule_confidence_threshold = 0.8;
    shared_model.ai_confidence_threshold = 0.6;
    shared_model.fusion_weights = struct('rule_weight', 0.6, 'ai_weight', 0.4);
    
    % Train once for all nodes
    shared_model = trainRandomForestModel(shared_model);
end
function node = cleanupMessageCache(node, current_time)
    message_ids = keys(node.message_cache);
    
    for i = 1:length(message_ids)
        msg_id = message_ids{i};
        cache_entry = node.message_cache(msg_id);
        
        if current_time - cache_entry.cache_time > node.cache_duration
            remove(node.message_cache, msg_id);
        end
    end
end

function has_message = nodeHasMessage(node, message_id)
    % Check if node already has this message in cache
    has_message = isKey(node.message_cache, message_id);
end

function node = forwardCachedMessages(node, current_time)
    % Check for new neighbors and forward cached messages
    message_ids = keys(node.message_cache);
    
    for i = 1:length(message_ids)
        msg_id = message_ids{i};
        cache_entry = node.message_cache(msg_id);
        
        % Check if message is still valid (not expired)
        if current_time - cache_entry.cache_time <= node.cache_duration
            % Find neighbors who haven't received this message yet
            for j = 1:length(node.neighbors)
                neighbor_id = node.neighbors(j);
                
                % Check if we haven't forwarded to this neighbor yet
                if ~ismember(neighbor_id, cache_entry.forwarded_to)
                    % Forward the message
                    fprintf('Node %d forwarding cached message %s to neighbor %d\n', ...
                        node.id, msg_id, neighbor_id);
                    
                    % Add to forwarded list
                    cache_entry.forwarded_to(end+1) = neighbor_id;
                    node.message_cache(msg_id) = cache_entry;
                    
                    % Update forwarded count for forwarding behavior tracking
                    node.forwarded_count = node.forwarded_count + 1;
                    
                    % Simulate forwarding (will be handled in main loop)
                end
            end
        end
    end
end

function logMessageDetails(message, detection_result, node, current_time)
    global message_log;
    
    % Initialize log if it doesn't exist
    if ~exist('message_log', 'var') || isempty(message_log)
        message_log = struct([]);
    end
    
    % Create detailed log entry
    log_entry = struct();
    
    % Basic message information
    log_entry.message_id = message.id;
    log_entry.timestamp = current_time;
    log_entry.source_id = message.source_id;
    log_entry.destination_id = message.destination_id;
    log_entry.message_type = message.type;
    log_entry.content = message.content;
    log_entry.content_length = length(message.content);
    log_entry.hop_count = message.hop_count;
    log_entry.ttl = message.ttl;
    log_entry.is_attack = message.is_attack;
    
    % Content analysis
    log_entry.entropy_score = calculateEntropy(message.content);
    log_entry.special_char_ratio = calculateSpecialCharRatio(message.content);
    log_entry.numeric_ratio = calculateNumericRatio(message.content);
    log_entry.emergency_keywords = countEmergencyKeywords(message.content);
    log_entry.suspicious_urls = countSuspiciousURLs(message.content);
    log_entry.command_patterns = countCommandPatterns(message.content);
    
    % Network context
    log_entry.detector_id = node.id;
    log_entry.detector_battery = node.battery_level;
    log_entry.detector_neighbors = length(node.neighbors);
    
    % Detection results
    if ~isempty(detection_result)
        log_entry.detected_as_attack = detection_result.is_attack;
        log_entry.detected_attack_type = detection_result.attack_type;
        log_entry.detection_confidence = detection_result.confidence;
        log_entry.threat_level = detection_result.threat_level;
        log_entry.processing_time_ms = detection_result.processing_time_ms;
        
        % Hybrid detection specific
        if isfield(detection_result, 'fusion_method')
            log_entry.fusion_method = detection_result.fusion_method;
            log_entry.rule_triggered = detection_result.rule_triggered;
            log_entry.rule_confidence = detection_result.rule_confidence;
            log_entry.ai_confidence = detection_result.ai_confidence;
        else
            % Ensure fields exist even if not hybrid detection
            log_entry.fusion_method = 'NOT_AVAILABLE';
            log_entry.rule_triggered = false;
            log_entry.rule_confidence = 0;
            log_entry.ai_confidence = 0;
        end
    else
        % No detection performed (e.g., message sent from sender node)
        log_entry.detected_as_attack = false;
        log_entry.detected_attack_type = 'NOT_ANALYZED';
        log_entry.detection_confidence = 0;
        log_entry.threat_level = 0;
        log_entry.processing_time_ms = 0;
        % Ensure hybrid fields exist for consistency
        log_entry.fusion_method = 'NOT_ANALYZED';
        log_entry.rule_triggered = false;
        log_entry.rule_confidence = 0;
        log_entry.ai_confidence = 0;
    end
    
    % Performance metrics
    log_entry.true_positive = log_entry.is_attack && log_entry.detected_as_attack;
    log_entry.true_negative = ~log_entry.is_attack && ~log_entry.detected_as_attack;
    log_entry.false_positive = ~log_entry.is_attack && log_entry.detected_as_attack;
    log_entry.false_negative = log_entry.is_attack && ~log_entry.detected_as_attack;
    
    % Add to log using safer approach
    if isempty(message_log)
        message_log = log_entry;
    else
        % Check if structures match, if not, add missing fields
        existing_fields = fieldnames(message_log);
        new_fields = fieldnames(log_entry);
        
        % Add missing fields to existing log entries
        missing_in_existing = setdiff(new_fields, existing_fields);
        for i = 1:length(missing_in_existing)
            field_name = missing_in_existing{i};
            % Add default values based on field type
            if strcmp(field_name, 'fusion_method') || strcmp(field_name, 'detected_attack_type')
                [message_log.(field_name)] = deal('MISSING');
            elseif strcmp(field_name, 'rule_triggered')
                [message_log.(field_name)] = deal(false);
            else
                [message_log.(field_name)] = deal(0);
            end
        end
        
        % Add missing fields to new log entry
        missing_in_new = setdiff(existing_fields, new_fields);
        for i = 1:length(missing_in_new)
            field_name = missing_in_new{i};
            % Add default values based on field type
            if strcmp(field_name, 'fusion_method') || strcmp(field_name, 'detected_attack_type')
                log_entry.(field_name) = 'MISSING';
            elseif strcmp(field_name, 'rule_triggered')
                log_entry.(field_name) = false;
            else
                log_entry.(field_name) = 0;
            end
        end
        
        % Now safely append
        message_log(end+1) = log_entry;
    end
end


function exportTrainingDataset()
    global message_log simulation_data;
    
    if isempty(message_log)
        fprintf('No message log data available for export.\n');
        return;
    end
    
    fprintf('Exporting comprehensive training dataset...\n');
    
    % Create results directory
    results_dir = 'training_data';
    if ~exist(results_dir, 'dir')
        mkdir(results_dir);
    end
    
    timestamp = datestr(now, 'yyyymmdd_HHMMSS');
    
    % Export detailed message log
    message_table = struct2table(message_log);
    csv_filename = fullfile(results_dir, sprintf('message_dataset_%s.csv', timestamp));
    writetable(message_table, csv_filename);
    fprintf('Message dataset exported to: %s\n', csv_filename);
    
    % Save as MAT file for MATLAB
    mat_filename = fullfile(results_dir, sprintf('message_log_%s.mat', timestamp));
    save(mat_filename, 'message_log');
    fprintf('Message log saved to: %s\n', mat_filename);
end

%% Main Simulation Function
function runBluetoothMeshSimulation()
    global simulation_data;
    global NUM_NORMAL_NODES NUM_ATTACK_NODES TOTAL_NODES MESSAGE_INTERVAL SIMULATION_TIME TRANSMISSION_RANGE AREA_SIZE ;
    global feature_log;
    global message_log; % Add global declaration for message_log
    
    % Initialize message_log as empty struct array
    message_log = struct([]);

    fprintf('Starting Bluetooth Mesh Network IDS Simulation...\n');
    fprintf('Network Configuration:\n');
    fprintf('- Normal Nodes: %d\n', NUM_NORMAL_NODES);
    fprintf('- Attacker Nodes: %d\n', NUM_ATTACK_NODES);
    fprintf('- Simulation Time: %d minutes\n', SIMULATION_TIME/60);
    fprintf('- Message Interval: %d seconds\n', MESSAGE_INTERVAL);
    fprintf('- Area Size: %dx%d meters\n\n', AREA_SIZE, AREA_SIZE);
    
    % Initialize nodes
    fprintf('Initializing network nodes...\n');
    nodes = [];
    fprintf('Training shared IDS model...\n');
    shared_ids_model = createSharedIDSModel();
    
    % Create normal nodes with random positions
    for i = 1:NUM_NORMAL_NODES
        [x, y] = getGridPosition(i, TOTAL_NODES, AREA_SIZE, TRANSMISSION_RANGE);

        
        node = createNormalNode(i, x, y);
        node.ids_model = shared_ids_model;  % ← SAME model for all
        nodes = [nodes, node];
    end
    
    % Create attacker nodes
    for i = 1:NUM_ATTACK_NODES
        [x, y] = getGridPosition(NUM_NORMAL_NODES + i, TOTAL_NODES, AREA_SIZE, TRANSMISSION_RANGE);

        
        attacker = createAdvancedAttackerNode(NUM_NORMAL_NODES + i, x, y);
        attacker.ids_model = shared_ids_model;  
        nodes = [nodes, attacker];
    end
    
    % Initialize neighbor relationships
    for i = 1:length(nodes)
        nodes(i) = updateNeighbors(nodes(i), nodes, TRANSMISSION_RANGE);
    end
    
    neighbor_counts = arrayfun(@(x) length(x.neighbors), nodes);
    fprintf('Network initialized with %d nodes.\n', length(nodes));
    fprintf('Average neighbors per node: %.2f\n\n', mean(neighbor_counts));
    

    % Simulation variables
    current_time = 0;
    last_message_time = 0;
    last_stats_time = 0;
    stats_history = struct([]);
    % Mobility variables
    next_mobility_time = randi([30,90]); % First random mobility event in 30-90 seconds

    fprintf('Starting simulation...\n\n');

    % Main simulation loop
    while current_time < SIMULATION_TIME
        simulation_data.current_time = current_time;

        % Random node mobility event
        fprintf('=== Mobility Event Check: current_time=%.1f, next_mobility_time=%.1f ===\n', current_time, next_mobility_time);
        if current_time >= next_mobility_time
            movable_indices = find([nodes.is_active]);
            if ~isempty(movable_indices)
                % Debug: Show list of active nodes and attacker status
                fprintf('>>> ACTIVE NODE LIST (at time %.1f): ', current_time);
                for idx = 1:length(movable_indices)
                    node_id = nodes(movable_indices(idx)).id;
                    if nodes(movable_indices(idx)).is_attacker
                        fprintf('[A%d] ', node_id);
                    else
                        fprintf('[N%d] ', node_id);
                    end
                end
                fprintf('\n');
                move_idx = movable_indices(randi(length(movable_indices)));
                % Calculate distance moved for tracking
                old_position = nodes(move_idx).position;
                % Move to a new random position within area
                nodes(move_idx).position = [AREA_SIZE*rand(), AREA_SIZE*rand()];
                % Update cumulative distance moved
                if isfield(nodes(move_idx), 'total_distance_moved')
                    distance_moved = norm(nodes(move_idx).position - old_position);
                    nodes(move_idx).total_distance_moved = nodes(move_idx).total_distance_moved + distance_moved;
                else
                    nodes(move_idx).total_distance_moved = 0; % Initialize if missing
                end
                % Update neighbors for this node and all others
                for j = 1:length(nodes)
                    nodes(j) = updateNeighbors(nodes(j), nodes, TRANSMISSION_RANGE);
                end
                fprintf('>>> Node %d moved to new position at time %.1f\n', nodes(move_idx).id, current_time);
            else
                fprintf('>>> No active nodes available for mobility at time %.1f\n', current_time);
            end
            % Schedule next mobility event
            next_mobility_time = current_time + randi([30,90]);
        end
        
        % Update network topology (simulate node mobility - optional)
        if mod(current_time, 60) == 0  % Update every minute
            for i = 1:length(nodes)
                nodes(i) = updateNeighbors(nodes(i), nodes, TRANSMISSION_RANGE);
            end
        end
        
        % Generate messages every MESSAGE_INTERVAL seconds
        if current_time - last_message_time >= MESSAGE_INTERVAL
            
            % ENHANCED: Generate multiple messages per interval to increase activity
            active_normal_indices = find(~[nodes.is_attacker] & [nodes.is_active]);
            
            if ~isempty(active_normal_indices)
                % Generate 1-2 messages per interval for faster testing
                num_messages = 1 + randi(2); % 1 to 2 messages
                
                for msg_count = 1:num_messages
                    % Randomly select a node to send a message
                    sender_idx = active_normal_indices(randi(length(active_normal_indices)));
                    
                    % Choose message type randomly
                    if rand() < 0.8  % 80% chance for data message
                        content = generateNormalMessage();
                        destination = randi(NUM_NORMAL_NODES);
                        if destination ~= nodes(sender_idx).id
                            [nodes(sender_idx), message] = sendMessage(nodes(sender_idx), content, 'DATA', destination, current_time);
                            if ~isempty(message)
                                % Log ALL messages, not just detected ones
                                logMessageDetails(message, [], nodes(sender_idx), current_time);
                                % Also log features for sent messages
                                logFeatureData(message, current_time, nodes(sender_idx), []);
                                fprintf('Network message: Node %d sent data message %s\n', nodes(sender_idx).id, message.id);
                            end
                        end
                    else  % 20% chance for heartbeat
                        [nodes(sender_idx), message] = sendMessage(nodes(sender_idx), 'HEARTBEAT', 'HEARTBEAT', 0, current_time);
                        if ~isempty(message)
                            % Log ALL messages, not just detected ones
                            logMessageDetails(message, [], nodes(sender_idx), current_time);
                            % Also log features for sent messages
                            logFeatureData(message, current_time, nodes(sender_idx), []);
                            fprintf('Network message: Node %d sent heartbeat %s\n', nodes(sender_idx).id, message.id);
                        end
                    end
                    
                    % Small delay between messages in the same interval
                    pause(0.1);
                end
            end
            
            last_message_time = current_time;
        end
        
        % Attacker actions
        attacker_indices = find([nodes.is_attacker] & [nodes.is_active]);
        normal_node_ids = [nodes(~[nodes.is_attacker]).id];
        
        for i = 1:length(attacker_indices)
            idx = attacker_indices(i);
            [nodes(idx), attack_message] = launchAttack(nodes(idx), current_time, normal_node_ids);
            
            % Log attack messages if they were generated
            if ~isempty(attack_message) && isstruct(attack_message) && isfield(attack_message, 'id')
                logMessageDetails(attack_message, [], nodes(idx), current_time);
                % Also log features for attack messages
                logFeatureData(attack_message, current_time, nodes(idx), nodes(idx));
                fprintf('ATTACK: Node %d launched %s attack with message %s\n', ...
                    nodes(idx).id, nodes(idx).attack_strategy, attack_message.id);
            end
        end
        
        % Enhanced message propagation with caching and duplicate detection
        if mod(current_time, 5) == 0  % Check every 5 seconds
            
            % Clean up expired messages from all nodes
            for i = 1:length(nodes)
                if nodes(i).is_active
                    nodes(i) = cleanupMessageCache(nodes(i), current_time);
                end
            end
            
            % Forward cached messages to new/missed neighbors
            for i = 1:length(nodes)
                if nodes(i).is_active && ~isempty(keys(nodes(i).message_cache))
                    % Check each cached message
                    message_ids = keys(nodes(i).message_cache);
                    
                    for j = 1:length(message_ids)
                        msg_id = message_ids{j};
                        cache_entry = nodes(i).message_cache(msg_id);
                        
                        % Skip if message expired
                        if current_time - cache_entry.cache_time > nodes(i).cache_duration
                            continue;
                        end
                        
                        % Forward to neighbors who don't have it yet
                        for k = 1:length(nodes(i).neighbors)
                            neighbor_id = nodes(i).neighbors(k);
                            neighbor_idx = find([nodes.id] == neighbor_id);
                            
                            if ~isempty(neighbor_idx) && nodes(neighbor_idx).is_active
                                % Check if neighbor already has this message
                                if ~nodeHasMessage(nodes(neighbor_idx), msg_id)
                                    if ~ismember(neighbor_id, cache_entry.forwarded_to)
                                        if rand() < 0.9  % 90% transmission success
                                            % Forward the message
                                            forwarded_msg = cache_entry.message;
                                            forwarded_msg.hop_count = forwarded_msg.hop_count + 1;
                                            forwarded_msg.ttl = forwarded_msg.ttl - 1;
                                            
                                            % Check TTL and maximum hop count limits
                                            MAX_HOP_COUNT = 10; % Maximum allowed hops in mesh network
                                            if forwarded_msg.ttl <= 0 || forwarded_msg.hop_count > MAX_HOP_COUNT
                                                fprintf('Message %s dropped: TTL=%d, hops=%d (max_hops=%d)\n', ...
                                                    msg_id, forwarded_msg.ttl, forwarded_msg.hop_count, MAX_HOP_COUNT);
                                                continue; % Skip forwarding this message
                                            end
            
                                            if neighbor_id ~= forwarded_msg.source_id
                                                [nodes(neighbor_idx), detection_result] = receiveMessage(nodes(neighbor_idx), forwarded_msg, current_time, nodes(i));
                                                
                                                % Increment forwarded count for the forwarding node
                                                if isfield(nodes(i), 'forwarded_count')
                                                    nodes(i).forwarded_count = nodes(i).forwarded_count + 1;
                                                else
                                                    nodes(i).forwarded_count = 1;
                                                end
                                                
                                                % Update feature log for this forwarding node to reflect current forwarding behavior
                                                updateForwardingBehaviorInLog(nodes(i), current_time);
                                                
                                                % Mark as forwarded to this neighbor
                                                cache_entry.forwarded_to(end+1) = neighbor_id;
                                                nodes(i).message_cache(msg_id) = cache_entry;
                                                
                                                % Also log features for forwarded messages from sender perspective
                                                logFeatureData(forwarded_msg, current_time, nodes(i), []);
                                                
                                                fprintf('Node %d forwarded cached message %s to Node %d (forwarded_count: %d)\n', ...
                                                    nodes(i).id, msg_id, neighbor_id, nodes(i).forwarded_count);
                                            else
                                                fprintf('Prevented forwarding message %s back to source Node %d\n', ...
                                                    msg_id, neighbor_id);
                                            end
                                        end
                                    end
                                end
                            end
                        end
                    end
                end
            end
        end
                
        % Update statistics every 30 seconds
        if current_time - last_stats_time >= 30
            updateStatistics(current_time);
            
            % Safe way to add to struct array
            if isempty(stats_history)
                stats_history = simulation_data.statistics;
            else
                stats_history(end+1) = simulation_data.statistics;
            end
            
            % Display current statistics with message generation info
            displayStatistics(simulation_data.statistics);
            
            % Show message generation stats
            global message_log;
            if ~isempty(message_log)
                recent_logs = message_log([message_log.timestamp] >= (current_time - 30));
                sent_messages = recent_logs(strcmp({recent_logs.detected_attack_type}, 'NOT_ANALYZED'));
                received_messages = recent_logs(~strcmp({recent_logs.detected_attack_type}, 'NOT_ANALYZED'));
                
                fprintf('>>> MESSAGE ACTIVITY (Last 30s): %d sent, %d received/analyzed <<<\n', ...
                    length(sent_messages), length(received_messages));
            end
            
            % Update visualizations
            visualizeNetwork(nodes, current_time);
            if length(stats_history) > 1
                plotRealTimeStatistics(stats_history);
            end
            
            last_stats_time = current_time;
        end
        
        % Battery depletion simulation
        if mod(current_time, 120) == 0  % Every 2 minutes
            for i = 1:length(nodes)
                nodes(i).battery_level = nodes(i).battery_level - 0.01; % 1% every 2 minutes
                if nodes(i).battery_level <= 0
                    nodes(i).is_active = false;
                    fprintf('Node %d ran out of battery at time %.1f\n', nodes(i).id, current_time);
                end
            end
        end
        
        % Time progression
        current_time = current_time + 1;
        pause(0.01); % Small delay for visualization
    end
    
    fprintf('\nExporting training dataset...\n');
    exportTrainingDataset();
    
    fprintf('\nExporting feature dataset...\n');
    exportFeatureDataset();

    fprintf('\nSimulation completed!\n');
    
    % Final statistics update
    updateStatistics(current_time);
    stats_history(end+1) = simulation_data.statistics;
    
    % Generate comprehensive report
    generateComprehensiveReport(nodes, stats_history);
    
    % Final visualizations
    visualizeNetwork(nodes, current_time);
    plotRealTimeStatistics(stats_history);
    
    % Save results
    saveSimulationResults(nodes, stats_history);

end



%% Run the simulation
fprintf('=== BLUETOOTH MESH NETWORK IDS SIMULATION ===\n');
fprintf('This simulation demonstrates AI-assisted intrusion detection\n');
fprintf('in a disaster-affected Bluetooth mesh network.\n\n');

% Set random seed for reproducibility
rng('shuffle');

% Run the main simulation
runBluetoothMeshSimulation();

fprintf('\nSimulation completed successfully!\n');
fprintf('Check the simulation_results folder for detailed output files.\n');

function updateForwardingBehaviorInLog(node, current_time)
    % Update forwarding_behavior in feature_log for recent entries from this node
    global feature_log;
    if isempty(feature_log)
        return;
    end
    
    % Calculate current forwarding behavior
    if isfield(node, 'forwarded_count') && isfield(node, 'received_count') && node.received_count > 0
        current_fwd_behavior = min(1, node.forwarded_count / node.received_count);
    else
        current_fwd_behavior = 0;
    end
    
    % Update recent entries (within last 30 seconds) from this node
    time_window = 30;
    for i = 1:length(feature_log)
        if feature_log(i).source_id == node.id && ...
           (current_time - feature_log(i).timestamp) <= time_window
            feature_log(i).features(40) = current_fwd_behavior;
        end
    end
end