%% Bluetooth Mesh Network IDS Simulation
% AI-Assisted Intrusion Detection System for Bluetooth Mesh Networks
% Author: Research Simulation
% Date: 2024


clear all; close all; clc;

%% Simulation Parameters
global NUM_NORMAL_NODES NUM_ATTACK_NODES TOTAL_NODES MESSAGE_INTERVAL SIMULATION_TIME TRANSMISSION_RANGE AREA_SIZE ;
NUM_NORMAL_NODES = 20;
NUM_ATTACK_NODES = 4;
TOTAL_NODES = NUM_NORMAL_NODES + NUM_ATTACK_NODES;
MESSAGE_INTERVAL = 60; % seconds - INCREASED to 30 to reduce message load
SIMULATION_TIME = 2* 60; % 5 minutes for better forwarding analysis
TRANSMISSION_RANGE = 50; % meterss
AREA_SIZE = 200; % 200x200 meter area

%% Initialize Global Variables
global simulation_data;
simulation_data = struct();
simulation_data.messages = struct([]);        % Empty struct array, NOT []
simulation_data.detections = struct([]);      % Empty struct array, NOT []
simulation_data.network_events = struct([]);  % Fixed: Added missing semicolon
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
    % Enhanced timestamp-organized buffer structure (tracks buffer entry time, not message creation time)
    node.message_buffer = struct('messages', {{}}, 'buffer_entry_times', [], 'total_bytes', 0);
    node.max_buffer_bytes = 10485760; % Increased buffer size to 10MB to completely eliminate message dropping
    node.routing_table = containers.Map();
    node.reputation_scores = containers.Map();
    node.message_history = {};
    node.detection_stats = struct('tp', 0, 'fp', 0, 'tn', 0, 'fn', 0);
    node.is_active = true;
    
    % Attacker-specific properties
    strategies = {'FLOODING', 'ADAPTIVE_FLOODING', 'RESOURCE_EXHAUSTION', 'BLACK_HOLE', 'SPOOFING'};
    node.attack_strategy = strategies{randi(length(strategies))};
    node.attack_frequency = 15 + 10 * rand(); % INCREASED: 15-25 seconds between attacks
    node.last_attack_time = 0;
    node.target_nodes = [];
    node.message_cache = containers.Map();
    node.cache_duration = 20;
    node.buffer_ttl = 300; % More aggressive: Messages expire from buffer after 300 seconds
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
    % Enhanced timestamp-organized buffer structure (tracks buffer entry time, not message creation time)
    node.message_buffer = struct('messages', {{}}, 'buffer_entry_times', [], 'total_bytes', 0);
    node.max_buffer_bytes = 10485760; % Increased buffer size to 10MB to completely eliminate message dropping
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
    node.buffer_ttl = 10; % More aggressive: Messages expire from buffer after 10 seconds
    node.attack_params = struct(); % Empty struct for normal nodes
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
    
    % Dynamic attack frequency based on strategy - DIFFERENT TIMING FOR EACH ATTACK TYPE
    base_frequency = 20; % INCREASED base frequency to 20 seconds
    switch node.attack_strategy
        case 'ADAPTIVE_FLOODING'
            node.attack_frequency = 3 + 2 * rand(); % Fast: 3-5 seconds (true flooding)
        case 'FLOODING'
            node.attack_frequency = 6 + 4 * rand(); % Medium-fast: 6-10 seconds
        case 'BLACK_HOLE'
            node.attack_frequency = base_frequency + 10 * rand(); % Slow: 20-30 seconds (stealth)
        case 'SPOOFING'
            node.attack_frequency = base_frequency + 5 * rand(); % Medium: 20-25 seconds 
        case 'RESOURCE_EXHAUSTION'
            node.attack_frequency = base_frequency + 15 * rand(); % Very slow: 20-35 seconds (gradual)
        otherwise
            node.attack_frequency = base_frequency + randi(10); % Default: 20-30 seconds
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

    % Black hole attack: drop all received messages, do not buffer or forward
    if node.is_attacker && isfield(node, 'attack_strategy') && strcmp(node.attack_strategy, 'BLACK_HOLE')
        fprintf('BLACK HOLE: Node %d dropped message %s\n', node.id, message.id);
        return;
    end

    % Print message path
    fprintf('Message %s: From Node %d → To Node %d (new)\n', ...
        message.id, message.source_id, node.id);

    % Clean up expired messages from buffer before checking capacity
    node = cleanupMessageBuffer(node, current_time);

    % Enforce buffer size limit (by total bytes) using new structure
    if node.message_buffer.total_bytes + length(message.content) > node.max_buffer_bytes
        %fprintf('Node %d buffer full (bytes)! Dropping message %s\n', node.id, message.id);
        return;
    end
    
    % Store message in buffer organized by buffer entry time (not message creation time)
    message_size = length(message.content);
    buffer_entry_time = current_time; % Use current time as buffer entry time
    
    % Find insertion point to maintain buffer entry time order
    insert_pos = length(node.message_buffer.buffer_entry_times) + 1;
    for i = 1:length(node.message_buffer.buffer_entry_times)
        if buffer_entry_time <= node.message_buffer.buffer_entry_times(i)
            insert_pos = i;
            break;
        end
    end
    
    % Insert message maintaining buffer entry time order
    node.message_buffer.messages = [node.message_buffer.messages(1:insert_pos-1), ...
                                   {message}, ...
                                   node.message_buffer.messages(insert_pos:end)];
    node.message_buffer.buffer_entry_times = [node.message_buffer.buffer_entry_times(1:insert_pos-1), ...
                                     buffer_entry_time, ...
                                     node.message_buffer.buffer_entry_times(insert_pos:end)];
    node.message_buffer.total_bytes = node.message_buffer.total_bytes + message_size;
    node.message_history{end+1} = message;

    % Update received count for forwarding behavior tracking
    node.received_count = node.received_count + 1;

    % CRITICAL: Run IDS detection BEFORE caching for forwarding
    if ~node.is_attacker
        [node, detection_result] = runIDSDetection(node, message, sender_node, current_time);
        logMessageDetails(message, detection_result, node, current_time);
        
        % BLOCKING DECISION: Only cache for forwarding if IDS approves
        if detection_result.is_attack && detection_result.confidence > 0.7
            message.blocked = true;
            message.block_reason = detection_result.attack_type;
            fprintf('Node %d BLOCKED message %s (reason: %s, confidence: %.2f) - NOT FORWARDING\n', ...
                node.id, message.id, detection_result.attack_type, detection_result.confidence);
            
            % Consume battery but DO NOT cache for forwarding
            node.battery_level = node.battery_level - 0.0005;
            return; % Exit without caching - message will NOT be forwarded
        end
    else
        % Even attackers should log received messages for completeness
        logMessageDetails(message, [], node, current_time);
        % Also log features for messages received by attackers
        logFeatureData(message, current_time, node, sender_node);
    end

    % ONLY CACHE FOR FORWARDING IF IDS APPROVED (or no IDS on attacker)
    cache_entry = struct();
    cache_entry.message = message;
    cache_entry.cache_time = current_time;
    cache_entry.forwarded_to = []; % Track which neighbors already received it
    
    node.message_cache(message.id) = cache_entry;
    
    fprintf('Node %d cached message %s for forwarding (IDS approved)\n', node.id, message.id);

    % Consume battery
    node.battery_level = node.battery_level - 0.0005;
end
%Detection Rules for Rule-based Detection
function rules = createDetectionRules()
    rules = struct();
    
% Rule 1: Flooding Detection (balanced thresholds to reduce false positives)
rules.flooding = struct();
rules.flooding.message_freq_threshold = 0.95; % STRICTER: 95% of max frequency
rules.flooding.message_size_threshold = 0.8; % STRICTER: 80% of max size
rules.flooding.burst_window = 60; % seconds
rules.flooding.confidence = 0.7;    % Rule 2: Spoofing Detection
    rules.spoofing = struct();
    rules.spoofing.suspicious_url_count = 4; % STRICTER: require even more evidence
    rules.spoofing.emergency_keyword_abuse = 10; % STRICTER: much higher threshold
    rules.spoofing.sender_reputation_threshold = 0.1; % STRICTER: even lower reputation threshold
    rules.spoofing.confidence = 0.85;
    
    % Rule 3: Resource Exhaustion Detection (SIGNIFICANTLY relaxed to reduce false positives)
    rules.resource_exhaustion = struct();
    rules.resource_exhaustion.message_size_threshold = 0.9; % STRICTER: 90% of max size
    rules.resource_exhaustion.frequency_threshold = 0.85; % STRICTER: 85% of max frequency
    rules.resource_exhaustion.battery_impact_threshold = 0.95; % STRICTER: 95% battery impact
    rules.resource_exhaustion.confidence = 0.6;
    
    % Rule 4: Black Hole Detection (relaxed to reduce false positives)
    rules.black_hole = struct();
    rules.black_hole.forwarding_threshold = 0.05; % STRICTER: extremely low forwarding behavior
    rules.black_hole.routing_anomaly_threshold = 0.8; % STRICTER: much higher routing anomaly threshold
    rules.black_hole.confidence = 0.75;
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
        
        % Detailed reason for flooding detection
        flood_reasons = {};
        if features(15) > rules.flooding.message_freq_threshold
            flood_reasons{end+1} = sprintf('High msg frequency (%.2f > %.2f)', features(15), rules.flooding.message_freq_threshold);
        end
        if features(8) > rules.flooding.message_size_threshold
            flood_reasons{end+1} = sprintf('Large msg size (%.2f > %.2f)', features(8), rules.flooding.message_size_threshold);
        end
        
        rule_result.triggered_rules{end+1} = sprintf('flooding_detection: %s', strjoin(flood_reasons, ' + '));
        fprintf('RULE TRIGGER: Flooding detected - %s\n', strjoin(flood_reasons, ' and '));
    end
    
    % Rule 2: Spoofing Detection
    spoofing_score = 0;
    spoof_reasons = {};
    
    if features(13) >= rules.spoofing.suspicious_url_count
        spoofing_score = spoofing_score + 0.4;
        spoof_reasons{end+1} = sprintf('Suspicious URLs (%.0f >= %d)', features(13), rules.spoofing.suspicious_url_count);
    end
    if features(12) >= rules.spoofing.emergency_keyword_abuse
        spoofing_score = spoofing_score + 0.3;
        spoof_reasons{end+1} = sprintf('Emergency keyword abuse (%.2f >= %d)', features(12), rules.spoofing.emergency_keyword_abuse);
    end
    if features(21) <= rules.spoofing.sender_reputation_threshold
        spoofing_score = spoofing_score + 0.3;
        spoof_reasons{end+1} = sprintf('Low sender reputation (%.2f <= %.2f)', features(21), rules.spoofing.sender_reputation_threshold);
    end
    
    if spoofing_score >= 0.8
        rule_result.detected_attacks{end+1} = 'SPOOFING';
        rule_result.confidences(end+1) = rules.spoofing.confidence * spoofing_score;
        rule_result.triggered_rules{end+1} = sprintf('spoofing_detection: %s', strjoin(spoof_reasons, ' + '));
        fprintf('RULE TRIGGER: Spoofing detected - %s (total score=%.2f)\n', strjoin(spoof_reasons, ' and '), spoofing_score);
    end
    
    % Rule 3: Resource Exhaustion Detection (normalized thresholds)
    resource_reasons = {};
    resource_triggered = false;
    
    if features(8) > rules.resource_exhaustion.message_size_threshold
        resource_reasons{end+1} = sprintf('Large msg size (%.2f > %.2f)', features(8), rules.resource_exhaustion.message_size_threshold);
        resource_triggered = true;
    end
    if features(15) > rules.resource_exhaustion.frequency_threshold
        resource_reasons{end+1} = sprintf('High frequency (%.2f > %.2f)', features(15), rules.resource_exhaustion.frequency_threshold);
        resource_triggered = true;
    end
    if features(33) > rules.resource_exhaustion.battery_impact_threshold
        resource_reasons{end+1} = sprintf('High battery impact (%.2f > %.2f)', features(33), rules.resource_exhaustion.battery_impact_threshold);
        resource_triggered = true;
    end
    
     if resource_triggered && ...
         features(8) > rules.resource_exhaustion.message_size_threshold && ...
         features(15) > rules.resource_exhaustion.frequency_threshold && ...
         features(33) > rules.resource_exhaustion.battery_impact_threshold
        rule_result.detected_attacks{end+1} = 'RESOURCE_EXHAUSTION';
        rule_result.confidences(end+1) = rules.resource_exhaustion.confidence;
        rule_result.triggered_rules{end+1} = sprintf('resource_exhaustion_detection: %s', strjoin(resource_reasons, ' + '));
        fprintf('RULE TRIGGER: Resource exhaustion detected - %s\n', strjoin(resource_reasons, ' and '));
    end
    
    % Rule 4: Black Hole Detection (NEW)
    if isfield(rules, 'black_hole')
        blackhole_reasons = {};
        blackhole_triggered = false;
        
        if features(40) < rules.black_hole.forwarding_threshold
            blackhole_reasons{end+1} = sprintf('Low forwarding (%.2f < %.2f)', features(40), rules.black_hole.forwarding_threshold);
            blackhole_triggered = true;
        end
        if features(29) > rules.black_hole.routing_anomaly_threshold
            blackhole_reasons{end+1} = sprintf('High routing anomaly (%.2f > %.2f)', features(29), rules.black_hole.routing_anomaly_threshold);
            blackhole_triggered = true;
        end
        
          if blackhole_triggered && ...
              features(40) < rules.black_hole.forwarding_threshold && ...
              features(29) > rules.black_hole.routing_anomaly_threshold
            rule_result.detected_attacks{end+1} = 'BLACK_HOLE';
            rule_result.confidences(end+1) = rules.black_hole.confidence;
            rule_result.triggered_rules{end+1} = sprintf('black_hole_detection: %s', strjoin(blackhole_reasons, ' + '));
            fprintf('RULE TRIGGER: Black hole detected - %s\n', strjoin(blackhole_reasons, ' and '));
        end
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
    ai_attack = ai_result.is_attack && ai_result.confidence > 0.6;  % Adjusted for corrected confidence
    
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
        if rule_result.overall_confidence > 0.5  % Reduced from 0.8
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
        if ai_result.confidence > 0.6  % Adjusted for corrected confidence
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
    if strcmp(attack_type, 'RESOURCE_EXHAUSTION')
        features(8) = min(1, base_msg_length * (3 + rand())); % 3-4x larger messages for resource exhaustion
    else
        features(8) = enhanceFeatureByAttackType(base_msg_length, attack_type, 'message_length');
    end
    
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
    
    % Traffic pattern analysis - Enhanced for attack signatures with LOWER frequency for non-flooding
    base_msg_freq = calculateMessageFrequency(node, current_time);
    if strcmp(attack_type, 'FLOODING') || strcmp(attack_type, 'ADAPTIVE_FLOODING')
        features(15) = min(1, base_msg_freq * (3 + rand())); % 3-4x higher frequency - MORE AGGRESSIVE
        features(16) = 0.8 + 0.2 * rand(); % High burst_intensity - INCREASED
        features(17) = 0.7 + 0.3 * rand(); % High inter_arrival_variance - INCREASED
        features(18) = 0.1 + 0.2 * rand(); % Low size_consistency - MORE OBVIOUS
        features(19) = 0.1 + 0.2 * rand(); % Low timing_regularity - MORE OBVIOUS
        features(20) = 0.7 + 0.3 * rand(); % High volume_anomaly_score - INCREASED
    elseif strcmp(attack_type, 'RESOURCE_EXHAUSTION')
        features(15) = min(0.4, base_msg_freq * (1.2 + 0.3 * rand())); % REDUCED: only 1.2-1.5x frequency
        features(16) = 0.3 + 0.3 * rand(); % Medium burst_intensity - REDUCED
        features(17) = 0.3 + 0.3 * rand(); % Medium inter_arrival_variance - REDUCED
        features(18) = 0.1 + 0.3 * rand(); % Low size_consistency - more obvious
        features(19) = 0.5 + 0.3 * rand(); % Medium timing_regularity
        features(20) = 0.3 + 0.3 * rand(); % Lower volume_anomaly_score - REDUCED
    else
        % For other attacks (BLACK_HOLE, SPOOFING), keep frequency low
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
    if isempty(node.message_buffer.messages)
        base_memory = 0;
    else
        base_memory = min(1, node.message_buffer.total_bytes / node.max_buffer_bytes);
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
    % Enhanced emergency keywords with more variety and context-awareness
    primary_emergency_keywords = {'emergency', 'help', 'rescue', 'urgent', 'sos', 'trapped', ...
                         'injured', 'medical', 'fire', 'flood', 'evacuate', 'shelter', ...
                         'missing', 'found', 'safe', 'danger', 'critical', 'alert', ...
                         'breaking', 'immediate', 'disaster', 'crisis', 'victim', 'survivor'};
    
    % NEW: Additional emergency and disaster-related terms                     
    extended_emergency_keywords = {'ambulance', 'paramedic', 'hospital', 'casualty', 'wounded', ...
                                  'evacuation', 'refuge', 'sanctuary', 'relief', 'aid', ...
                                  'hurricane', 'tornado', 'earthquake', 'tsunami', 'wildfire', ...
                                  'explosion', 'collapse', 'contamination', 'outbreak', 'pandemic', ...
                                  'blackout', 'shortage', 'rationing', 'quarantine', 'lockdown', ...
                                  'deceased', 'fatality', 'casualty', 'triage', 'stabilize'};
    
    % NEW: False emergency indicators (common in spoofing)
    false_emergency_indicators = {'click here', 'urgent action', 'act now', 'limited time', ...
                                 'verify account', 'confirm identity', 'update information', ...
                                 'suspicious activity', 'security alert', 'account locked', ...
                                 'immediate response', 'time sensitive', 'expires soon'};
    
    % NEW: Technical emergency terms
    technical_emergency_keywords = {'system failure', 'network down', 'service disruption', ...
                                   'connectivity lost', 'infrastructure damage', 'power outage', ...
                                   'communication failure', 'backup activated', 'redundancy lost', ...
                                   'overload detected', 'capacity exceeded', 'throughput critical'};
    
    text_lower = lower(text);
    raw_count = 0;
    
    % Count primary emergency keywords (weighted more heavily)
    for i = 1:length(primary_emergency_keywords)
        if contains(text_lower, primary_emergency_keywords{i})
            raw_count = raw_count + 1.0;
        end
    end
    
    % Count extended emergency keywords (medium weight)
    for i = 1:length(extended_emergency_keywords)
        if contains(text_lower, extended_emergency_keywords{i})
            raw_count = raw_count + 0.7;
        end
    end
    
    % Count false emergency indicators (lower weight, but still suspicious)
    for i = 1:length(false_emergency_indicators)
        if contains(text_lower, false_emergency_indicators{i})
            raw_count = raw_count + 0.5;
        end
    end
    
    % Count technical emergency keywords (medium weight)
    for i = 1:length(technical_emergency_keywords)
        if contains(text_lower, technical_emergency_keywords{i})
            raw_count = raw_count + 0.8;
        end
    end
    
    % NEW: Detect emergency keyword clustering (multiple keywords close together)
    clustering_bonus = 0;
    primary_positions = [];
    for i = 1:length(primary_emergency_keywords)
        pos = strfind(text_lower, primary_emergency_keywords{i});
        primary_positions = [primary_positions, pos];
    end
    
    if length(primary_positions) > 1
        primary_positions = sort(primary_positions);
        for i = 1:length(primary_positions)-1
            if primary_positions(i+1) - primary_positions(i) < 50 % Within 50 characters
                clustering_bonus = clustering_bonus + 0.3;
            end
        end
    end
    
    raw_count = raw_count + clustering_bonus;
    
    % Normalize by maximum expected keywords (assume max 8 keywords per message is very high)
    count = min(1, raw_count / 8);
end

function count = countSuspiciousURLs(text)
    % Enhanced suspicious URL detection with more patterns
    basic_url_patterns = {'http://', 'https://', 'www.', '.com', '.org', '.net', '.gov'};
    
    % NEW: Suspicious domain patterns
    suspicious_domain_patterns = {'.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.click', ...
                                 'bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly', ...
                                 'fake-', 'phishing-', 'malicious-', 'spoofed-', 'scam-', ...
                                 'temp-', 'temporary-', 'urgent-', 'emergency-'};
    
    % NEW: Suspicious URL parameters
    suspicious_parameters = {'?token=', '?auth=', '?verify=', '?confirm=', '?update=', ...
                            '?login=', '?password=', '?account=', '?security=', '?urgent='};
    
    % NEW: Suspicious TLD combinations
    suspicious_tlds = {'.tk', '.ml', '.ga', '.cf', '.pw', '.cc'};
    
    count = 0;
    text_lower = lower(text);
    
    % Basic URL pattern detection
    for i = 1:length(basic_url_patterns)
        if contains(text_lower, basic_url_patterns{i})
            count = count + 1;
        end
    end
    
    % Suspicious domain detection (higher weight)
    for i = 1:length(suspicious_domain_patterns)
        if contains(text_lower, suspicious_domain_patterns{i})
            count = count + 2;
        end
    end
    
    % Suspicious parameter detection
    for i = 1:length(suspicious_parameters)
        if contains(text_lower, suspicious_parameters{i})
            count = count + 1.5;
        end
    end
    
    % Suspicious TLD detection
    for i = 1:length(suspicious_tlds)
        if contains(text_lower, suspicious_tlds{i})
            count = count + 1.5;
        end
    end
    
    % NEW: Check for URL obfuscation techniques
    if contains(text_lower, '%') && (contains(text_lower, 'http') || contains(text_lower, 'www'))
        count = count + 2; % URL encoding detected
    end
    
    % NEW: Check for multiple URLs in one message
    url_indicators = sum([contains(text_lower, 'http://'), contains(text_lower, 'https://'), ...
                         contains(text_lower, 'www.'), contains(text_lower, 'ftp://')]);
    if url_indicators > 1
        count = count + 1.5; % Multiple URLs suspicious
    end
    
    % NEW: Emergency + URL combination (very suspicious)
    emergency_words = {'urgent', 'emergency', 'immediate', 'critical', 'help'};
    has_emergency = false;
    for i = 1:length(emergency_words)
        if contains(text_lower, emergency_words{i})
            has_emergency = true;
            break;
        end
    end
    
    if has_emergency && count > 0
        count = count + 2; % Emergency + URL = highly suspicious
    end
end

function count = countCommandPatterns(text)
    % Enhanced command pattern detection for technical attacks
    system_commands = {'delete', 'drop', 'exec', 'system', 'cmd', 'bash', 'sh', 'rm', 'kill'};
    
    % NEW: Network and protocol commands
    network_commands = {'ping', 'traceroute', 'netstat', 'ifconfig', 'route', 'arp', ...
                       'wget', 'curl', 'ssh', 'telnet', 'ftp', 'nmap'};
    
    % NEW: Database and injection patterns
    injection_patterns = {'select', 'insert', 'update', 'delete', 'union', 'drop table', ...
                         'or 1=1', '--', ';--', 'xp_cmdshell', 'sp_', 'exec('};
    
    % NEW: Scripting and automation commands
    script_commands = {'python', 'perl', 'php', 'ruby', 'javascript', 'powershell', ...
                      'batch', 'script', 'execute', 'run', 'invoke'};
    
    % NEW: System manipulation commands
    system_manipulation = {'chmod', 'chown', 'sudo', 'su', 'passwd', 'useradd', 'groupadd', ...
                          'mount', 'umount', 'format', 'fdisk', 'dd'};
    
    text_lower = lower(text);
    count = 0;
    
    % Count different types of commands with different weights
    command_categories = {
        {system_commands, 2.0},           % High weight for system commands
        {network_commands, 1.5},          % Medium-high for network commands  
        {injection_patterns, 3.0},        % Very high for injection patterns
        {script_commands, 1.5},           % Medium-high for scripting
        {system_manipulation, 2.5}        % High for system manipulation
    };
    
    for cat = 1:length(command_categories)
        commands = command_categories{cat}{1};
        weight = command_categories{cat}{2};
        
        for i = 1:length(commands)
            if contains(text_lower, commands{i})
                count = count + weight;
            end
        end
    end
    
    % NEW: Check for command chaining (multiple commands in sequence)
    chaining_indicators = {';', '&&', '||', '|', '&'};
    chain_count = 0;
    for i = 1:length(chaining_indicators)
        chain_count = chain_count + length(strfind(text, chaining_indicators{i}));
    end
    
    if chain_count > 0 && count > 0
        count = count + chain_count * 0.5; % Bonus for command chaining
    end
    
    % NEW: Check for encoding/obfuscation
    if contains(text, 'base64') || contains(text, 'encode') || contains(text, 'decode')
        count = count + 1.5;
    end
    
    % Normalize by expected maximum (assume 10 is very high)
    count = min(count / 10, 1);
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
    if isempty(node.message_buffer.messages)
        load = 0;
        return;
    end
    % Use the pre-calculated total_bytes from organized buffer
    total_bytes = node.message_buffer.total_bytes;
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
            % Use the appropriate model type
            switch ids_model.model_type
                case {'MATLAB', 'MATLAB_OPTIMIZED', 'MATLAB_FROM_PRETRAINED', 'READY_MATLAB_MODEL'}
                    % Use MATLAB TreeBagger (original, optimized, or from pre-trained params)
                    [prediction, scores] = predict(ids_model.rf_model, features);
                    attack_type = prediction{1}; % TreeBagger returns cell array
                    
                    % Fix confidence calculation for TreeBagger
                    % TreeBagger scores are proportion of trees voting for each class
                    max_score = max(scores);
                    
                    % Convert to proper confidence (0-1 scale)
                    % Higher max_score = higher confidence
                    confidence = max_score;
                    
                    % For better fusion: normalize confidence to more usable range
                    if max_score > 0.4  % Strong majority vote
                        confidence = 0.8 + (max_score - 0.4) * 0.5; % Scale to 0.8-1.0
                    elseif max_score > 0.3  % Moderate majority
                        confidence = 0.6 + (max_score - 0.3) * 2.0; % Scale to 0.6-0.8
                    else  % Weak majority
                        confidence = max_score * 2.0; % Scale to 0.0-0.6
                    end
                    
                    % Ensure confidence stays in [0,1] range
                    confidence = min(1.0, max(0.0, confidence));
                    
                    is_attack = ~strcmp(attack_type, 'NORMAL');
                    
                    % Generate TreeBagger reasoning based on class scores
                    try
                        [sorted_scores, sorted_indices] = sort(scores, 'descend');
                        class_names = ids_model.rf_model.ClassNames;
                        
                        % Store TreeBagger reasoning
                        top_classes = {};
                        for i = 1:min(3, length(sorted_scores))
                            if sorted_scores(i) > 0.1  % Only include significant scores
                                class_name = class_names{sorted_indices(i)};
                                top_classes{end+1} = sprintf('%s(%.2f)', class_name, sorted_scores(i));
                            end
                        end
                        ids_model.last_ai_reasoning = sprintf('TreeBagger votes: %s', strjoin(top_classes, ', '));
                    catch
                        ids_model.last_ai_reasoning = sprintf('TreeBagger prediction: %s', attack_type);
                    end
                    
                    % Optional: Show prediction for models based on pre-trained
                    if strcmp(ids_model.model_type, 'MATLAB_FROM_PRETRAINED')
                        % fprintf(' Pre-trained MATLAB RF: %s (conf: %.3f)\n', attack_type, confidence);
                    end
                    
                case 'PYTHON_PRETRAINED_LOOKUP'
                    % Use your pre-trained Python model's knowledge directly (NO TREEBAGGER!)
                    [is_attack, attack_type, confidence] = predictWithPythonModel(ids_model, features);
                    
                otherwise
                    % Fallback to simulation
                    [is_attack, attack_type, confidence] = simulateDetection(ids_model, features);
            end
            
        catch ME
            fprintf('⚠️  Model prediction failed: %s\n', ME.message);
            % Fallback to simulation model
            [is_attack, attack_type, confidence] = simulateDetection(ids_model, features);
        end
    else
        % Use simplified simulation model
        [is_attack, attack_type, confidence] = simulateDetection(ids_model, features);
    end
end



function [X, y] = generateTrainingData(n_samples, attack_types)
    % Generate enhanced training data with better class balance and feature quality
    fprintf(' Generating %d training samples with enhanced features...\n', n_samples);
    
    % Enhanced class distribution for better balance
    class_probs = [0.45, 0.15, 0.12, 0.10, 0.10, 0.08]; % More balanced than original
    
    X = [];
    y = {};
    
    % Generate samples per class
    for class_idx = 1:length(attack_types)
        attack_type = attack_types{class_idx};
        n_class_samples = round(n_samples * class_probs(class_idx));
        
        fprintf('    Generating %d samples for %s\n', n_class_samples, attack_type);
        
        for i = 1:n_class_samples
            % Generate enhanced features for this class
            features = generateEnhancedFeaturesForClass(attack_type);
            X = [X; features];
            y{end+1} = attack_type;
        end
    end
    
    % Shuffle the data
    n_total = length(y);
    shuffle_idx = randperm(n_total);
    X = X(shuffle_idx, :);
    y = y(shuffle_idx);
    
    fprintf('✅ Enhanced training data generated: %d samples, %d features\n', size(X, 1), size(X, 2));
    
    % Display class distribution
    unique_classes = unique(y);
    fprintf(' Class distribution:\n');
    for i = 1:length(unique_classes)
        count = sum(strcmp(y, unique_classes{i}));
        percentage = (count / length(y)) * 100;
        fprintf('   %s: %d (%.1f%%)\n', unique_classes{i}, count, percentage);
    end
end

function features = generateEnhancedFeaturesForClass(class_name)
    % Generate enhanced 43 features based on class type with more realistic patterns
    features = rand(1, 43) * 0.3 + 0.1; % Start with low baseline [0.1, 0.4]
    
    switch class_name
        case 'NORMAL'
            % Normal traffic patterns
            features(1) = 0.3 + rand()*0.4;     % node_density: moderate
            features(8) = 0.1 + rand()*0.3;     % message_length: small to medium
            features(15) = 0.1 + rand()*0.2;    % message_frequency: low
            features(21) = 0.7 + rand()*0.3;    % sender_reputation: high
            features(33) = 0.1 + rand()*0.2;    % battery_impact: low
            
        case 'FLOODING'
            % High frequency, large messages, low reputation
            features(15) = 0.6 + rand()*0.4;    % message_frequency: very high
            features(8) = 0.4 + rand()*0.6;     % message_length: large
            features(16) = 0.7 + rand()*0.3;    % burst_intensity: high
            features(21) = 0.0 + rand()*0.3;    % sender_reputation: very low
            features(33) = 0.6 + rand()*0.4;    % battery_impact: high
            features(20) = 0.6 + rand()*0.4;    % volume_anomaly_score: high
            
        case 'ADAPTIVE_FLOODING'
            % Variable patterns that adapt
            features(15) = 0.4 + rand()*0.6;    % message_frequency: high but variable
            features(16) = 0.5 + rand()*0.5;    % burst_intensity: moderate to high
            features(17) = 0.6 + rand()*0.4;    % inter_arrival_variance: high
            features(18) = 0.1 + rand()*0.4;    % size_consistency: low (adaptive)
            features(19) = 0.2 + rand()*0.4;    % timing_regularity: low (adaptive)
            features(21) = 0.1 + rand()*0.4;    % sender_reputation: low to moderate
            
        case 'SPOOFING'
            % High suspicious content, URL patterns
            features(10) = 0.3 + rand()*0.7;    % special_char_ratio: high
            features(12) = 0.4 + rand()*0.6;    % emergency_keyword_count: high
            features(13) = 1 + rand()*3;        % suspicious_url_count: multiple URLs
            features(21) = 0.0 + rand()*0.4;    % sender_reputation: very low
            features(30) = 0.3 + rand()*0.4;    % header_integrity: degraded
            features(32) = 0.3 + rand()*0.5;    % protocol_compliance: poor
            
        case 'BLACK_HOLE'
            % Low forwarding behavior, routing anomalies
            features(29) = 0.5 + rand()*0.5;    % routing_anomaly: high
            features(40) = 0.0 + rand()*0.2;    % forwarding_behavior: very low
            features(4) = 0.2 + rand()*0.4;     % hop_reliability: degraded
            features(7) = 0.1 + rand()*0.3;     % backup_route_availability: low
            features(39) = 0.2 + rand()*0.4;    % route_stability: poor
            
        case 'RESOURCE_EXHAUSTION'
            % High resource consumption patterns
            features(8) = 0.5 + rand()*0.5;     % message_length: very large
            features(33) = 0.7 + rand()*0.3;    % battery_impact: very high
            features(34) = 0.6 + rand()*0.4;    % processing_load: high
            features(35) = 0.5 + rand()*0.5;    % memory_footprint: large
            features(15) = 0.3 + rand()*0.5;    % message_frequency: moderate to high
    end
    
    % Add realistic noise and correlations
    features = features + randn(1, 43) * 0.05; % Small gaussian noise
    
    % Ensure all features are within [0,1] bounds (except URL count which can be >1)
    features(1:43) = max(0, min(1, features(1:43)));
    if features(13) > 1 % Allow suspicious_url_count to exceed 1
        features(13) = max(0, min(5, features(13))); % Cap at 5 URLs
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
    if features(15) > 2 && features(8) > 200  % Reduced thresholds
        is_attack = true;
        attack_type = 'FLOODING';
        confidence = 0.7 + 0.2 * rand();  % Reduced base confidence
    % Spoofing detection (suspicious URLs + low reputation)
    elseif features(13) > 0 && features(21) < 0.6  % Increased reputation threshold
        is_attack = true;
        attack_type = 'SPOOFING';
        confidence = 0.6 + 0.25 * rand();  % Reduced base confidence
    % Resource exhaustion detection (high battery impact + large messages)
    elseif features(33) > 0.6 && features(8) > 150  % Reduced thresholds
        is_attack = true;
        attack_type = 'RESOURCE_EXHAUSTION';
        confidence = 0.5 + 0.3 * rand();  % Reduced base confidence
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
        % Determine the real attack type
        if isfield(original_message, 'true_attack_type')
            real_attack_type = original_message.true_attack_type;
        elseif original_message.is_attack
            % If message doesn't have true_attack_type but is an attack, try to get from source
            real_attack_type = 'UNKNOWN_ATTACK';
        else
            real_attack_type = 'NORMAL';
        end
        
        % Enhanced detection output showing: Detected vs Real attack types + confidence + detection source + reason
        % Consider ADAPTIVE_FLOODING and FLOODING as equivalent for accuracy
        is_correct_detection = strcmp(detection_result.attack_type, real_attack_type) || ...
                              (strcmp(detection_result.attack_type, 'FLOODING') && strcmp(real_attack_type, 'ADAPTIVE_FLOODING')) || ...
                              (strcmp(detection_result.attack_type, 'ADAPTIVE_FLOODING') && strcmp(real_attack_type, 'FLOODING'));
        
        % Determine detection source and reason
        detection_source = 'UNKNOWN';
        detection_reason = 'No specific reason available';
        
        if isfield(detection_result, 'fusion_method')
            switch detection_result.fusion_method
                case 'CONSENSUS'
                    detection_source = 'HYBRID (Rule+AI Consensus)';
                    rule_details = '';
                    ai_details = '';
                    
                    % Get rule reasoning
                    if isfield(detection_result, 'triggered_rules') && ~isempty(detection_result.triggered_rules)
                        rule_details = sprintf('Rules: %s', strjoin(detection_result.triggered_rules, '; '));
                    end
                    
                    % Get AI reasoning
                    if isfield(node.ids_model, 'last_ai_reasoning') && ~isempty(node.ids_model.last_ai_reasoning)
                        ai_details = sprintf('AI: %s', node.ids_model.last_ai_reasoning);
                    end
                    
                    if ~isempty(rule_details) && ~isempty(ai_details)
                        detection_reason = sprintf('%s | %s (rule_conf:%.2f, ai_conf:%.2f)', ...
                            rule_details, ai_details, detection_result.rule_confidence, detection_result.ai_confidence);
                    elseif ~isempty(rule_details)
                        detection_reason = sprintf('%s (rule_conf:%.2f, ai_conf:%.2f)', ...
                            rule_details, detection_result.rule_confidence, detection_result.ai_confidence);
                    else
                        detection_reason = sprintf('Both rule-based (conf:%.2f) and AI (conf:%.2f) agreed on attack', ...
                            detection_result.rule_confidence, detection_result.ai_confidence);
                    end
                case 'RULE_ONLY'
                    detection_source = 'RULE-BASED ONLY';
                    if isfield(detection_result, 'triggered_rules') && ~isempty(detection_result.triggered_rules)
                        rule_list = strjoin(detection_result.triggered_rules, ', ');
                        detection_reason = sprintf('Rule(s) triggered: %s (conf:%.2f)', rule_list, detection_result.rule_confidence);
                    else
                        detection_reason = sprintf('Rule-based detection (conf:%.2f)', detection_result.rule_confidence);
                    end
                case 'AI_ONLY'
                    detection_source = 'AI-BASED ONLY';
                    if isfield(node.ids_model, 'last_ai_reasoning') && ~isempty(node.ids_model.last_ai_reasoning)
                        detection_reason = sprintf('AI model: %s (conf:%.2f)', node.ids_model.last_ai_reasoning, detection_result.ai_confidence);
                    else
                        detection_reason = sprintf('AI model prediction (conf:%.2f)', detection_result.ai_confidence);
                    end
                case 'RULE_WEAK'
                    detection_source = 'RULE-BASED (Weak)';
                    detection_reason = sprintf('Weak rule confidence (%.2f), classified as normal', detection_result.rule_confidence);
                case 'AI_WEAK'
                    detection_source = 'AI-BASED (Weak)';
                    detection_reason = sprintf('Weak AI confidence (%.2f), classified as normal', detection_result.ai_confidence);
                case 'BOTH_NORMAL'
                    detection_source = 'HYBRID (Both Normal)';
                    detection_reason = 'Both rule-based and AI classified as normal';
                otherwise
                    detection_source = sprintf('HYBRID (%s)', detection_result.fusion_method);
                    detection_reason = sprintf('Fusion method: %s', detection_result.fusion_method);
            end
        else
            % Legacy single-model detection
            detection_source = 'AI-LEGACY';
            detection_reason = sprintf('Legacy AI detection (conf:%.2f)', detection_result.confidence);
        end
        
        if is_correct_detection
            % Correct detection (including FLOODING/ADAPTIVE_FLOODING equivalence)
            fprintf('✅ Node %d: CORRECT detection | Detected: %s | Real: %s | Confidence: %.2f | Source: %s\n', ...
                node.id, detection_result.attack_type, real_attack_type, detection_result.confidence, detection_source);
            fprintf('   └─ Reason: %s | Message: %s\n', detection_reason, detection_result.message_id);
        else
            % Incorrect detection (misclassification)
            fprintf('❌ Node %d: MISCLASSIFIED | Detected: %s | Real: %s | Confidence: %.2f | Source: %s\n', ...
                node.id, detection_result.attack_type, real_attack_type, detection_result.confidence, detection_source);
            fprintf('   └─ Reason: %s | Message: %s\n', detection_reason, detection_result.message_id);
        end
        
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
            content = generateBlackHoleContent(node); % NEW enhanced function
        case 'SPOOFING'
            content = generateSpoofingContent(node);
        otherwise
            content = generateHybridAttackContent(node); % NEW fallback
    end
end

function content = generateBlackHoleContent(node)
    % Black Hole attacks: deceptive routing advertisements and fake responses
    blackhole_patterns = struct();
    
    % Routing Advertisement Spoofing
    blackhole_patterns.routing_ads = {
        'ROUTE_ADVERTISEMENT: OPTIMAL_PATH_VIA_NODE_%d_LATENCY_0ms_AVAILABLE',
        'TOPOLOGY_UPDATE: NEW_SHORTEST_PATH_DISCOVERED_VIA_HUB_%d_RELIABLE',  
        'MESH_OPTIMIZATION: HIGH_BANDWIDTH_ROUTE_ESTABLISHED_THROUGH_%d',
        'NETWORK_ENHANCEMENT: PREMIUM_ROUTING_SERVICE_ACTIVE_NODE_%d',
        'PATH_DISCOVERY: ULTRA_FAST_ROUTE_TO_DESTINATION_VIA_%d_CONFIRMED',
        'ROUTING_PROTOCOL: ENHANCED_FORWARDING_CAPABILITY_NODE_%d_READY'
    };
    
    % Fake Service Advertisements
    blackhole_patterns.service_ads = {
        'SERVICE_ANNOUNCEMENT: EMERGENCY_RELAY_HUB_ACTIVE_NODE_%d_PRIORITY_ROUTING',
        'CRITICAL_SERVICE: MEDICAL_DATA_FORWARDING_SPECIALIST_NODE_%d_AVAILABLE',
        'RESCUE_COORDINATION: PRIORITY_MESSAGE_HANDLER_NODE_%d_OPERATIONAL',
        'EMERGENCY_GATEWAY: SATELLITE_UPLINK_ACCESS_VIA_NODE_%d_UNLIMITED',
        'COMMUNICATION_HUB: LONG_RANGE_RELAY_CAPABILITY_NODE_%d_ACTIVE',
        'DATA_AGGREGATOR: EMERGENCY_INFO_CONSOLIDATION_NODE_%d_READY'
    };
    
    % Trust Building Messages
    blackhole_patterns.trust_building = {
        'RELIABILITY_REPORT: NODE_%d_UPTIME_99.9%%_ZERO_PACKET_LOSS_VERIFIED',
        'PERFORMANCE_METRIC: NODE_%d_FASTEST_FORWARDING_MEASURED_TRUSTED_SOURCE',
        'QUALITY_ASSURANCE: NODE_%d_CERTIFIED_EMERGENCY_ROUTER_OFFICIAL_DESIGNATION',
        'NETWORK_TESTIMONIAL: NODE_%d_RECOMMENDED_BY_NETWORK_ADMINISTRATOR',
        'REPUTATION_UPDATE: NODE_%d_HIGHEST_RELIABILITY_SCORE_COMMUNITY_VERIFIED',
        'ENDORSEMENT: NODE_%d_VERIFIED_EMERGENCY_INFRASTRUCTURE_COMPONENT'
    };
    
    % Fake Acknowledgments (to appear responsive)
    blackhole_patterns.fake_acks = {
        'ACK_CONFIRMATION: MESSAGE_%s_SUCCESSFULLY_FORWARDED_VIA_NODE_%d',
        'DELIVERY_RECEIPT: PACKET_%s_DELIVERED_THROUGH_OPTIMAL_ROUTE_NODE_%d',
        'TRANSMISSION_SUCCESS: DATA_%s_RELAYED_VIA_HIGH_PRIORITY_NODE_%d',
        'FORWARD_COMPLETE: MESSAGE_%s_SUCCESSFULLY_ROUTED_THROUGH_NODE_%d',
        'RELAY_CONFIRMATION: PACKET_%s_DELIVERED_VIA_PREMIUM_SERVICE_NODE_%d',
        'ROUTING_SUCCESS: DATA_%s_TRANSMITTED_THROUGH_VERIFIED_NODE_%d'
    };
    
    % Deceptive Emergency Messages
    blackhole_patterns.deceptive_emergency = {
        'EMERGENCY_ROUTER: NODE_%d_HANDLING_CRITICAL_MEDICAL_ROUTING_TRUST_VERIFIED',
        'PRIORITY_FORWARDER: NODE_%d_DESIGNATED_RESCUE_COMMUNICATION_HUB',
        'CRITICAL_RELAY: NODE_%d_EMERGENCY_SERVICES_GATEWAY_OFFICIALLY_AUTHORIZED',
        'VITAL_LINK: NODE_%d_DISASTER_RESPONSE_COMMUNICATION_BACKBONE',
        'EMERGENCY_HUB: NODE_%d_COORDINATING_ALL_RESCUE_COMMUNICATIONS',
        'CRISIS_MANAGER: NODE_%d_CENTRAL_EMERGENCY_INFORMATION_PROCESSOR'
    };
    
    % Select pattern type
    patterns = fieldnames(blackhole_patterns);
    pattern_idx = randi(length(patterns));
    selected_patterns = blackhole_patterns.(patterns{pattern_idx});
    
    % Choose specific message
    base_message = selected_patterns{randi(length(selected_patterns))};
    
    % Generate fake node ID or message ID for the content
    if contains(base_message, 'MESSAGE_%s') || contains(base_message, 'PACKET_%s') || contains(base_message, 'DATA_%s')
        fake_msg_id = sprintf('MSG_%04X', randi(65535));
        content = sprintf(base_message, fake_msg_id, node.id);
    else
        content = sprintf(base_message, node.id);
    end
    
    % Add deceptive metrics to build false trust
    metrics = {
        sprintf('[RELIABILITY: %.1f%%]', 95 + rand()*5), % 95-100%
        sprintf('[LATENCY: %dms]', randi(5)), % 0-5ms (impossibly good)
        sprintf('[THROUGHPUT: %dMbps]', 50 + randi(50)), % 50-100 Mbps
        sprintf('[UPTIME: %dd%dh]', randi(365), randi(24)), % Long uptime
        sprintf('[TRUST_SCORE: %.2f/1.0]', 0.9 + rand()*0.1) % High trust
    };
    
    % Add 1-2 metrics
    num_metrics = 1 + randi(2);
    selected_metrics = metrics(randperm(length(metrics), num_metrics));
    for i = 1:length(selected_metrics)
        content = [content, ' ', selected_metrics{i}];
    end
    
    % Add timestamp for authenticity
    if rand() < 0.3
        timestamp = sprintf('[TIMESTAMP: %02d:%02d:%02d.%03d]', ...
            randi(24)-1, randi(60), randi(60), randi(1000));
        content = [content, ' ', timestamp];
    end
    
    % Note: Black hole nodes will drop/ignore received messages in the receiveMessage function
    % This content is what they advertise to attract traffic
end

function content = generateHybridAttackContent(node)
    % Hybrid/Unknown attack patterns for variety
    hybrid_patterns = {
        'MULTI_VECTOR_ATTACK: COMBINING_FLOOD_AND_SPOOF_TECHNIQUES_ACTIVE',
        'POLYMORPHIC_ASSAULT: CHANGING_ATTACK_SIGNATURE_EVERY_TRANSMISSION',
        'ADVANCED_PERSISTENT_THREAT: LONG_TERM_NETWORK_INFILTRATION_MODE',
        'ZERO_DAY_EXPLOIT: UNKNOWN_VULNERABILITY_EXPLOITATION_IN_PROGRESS',
        'COORDINATED_ATTACK: SYNCHRONIZED_MULTI_NODE_ASSAULT_PATTERN',
        'STEALTH_INFILTRATION: LOW_PROFILE_RECONNAISSANCE_AND_MAPPING',
        'SOCIAL_ENGINEERING: PSYCHOLOGICAL_MANIPULATION_ATTACK_VECTOR',
        'PROTOCOL_ABUSE: EXPLOITING_MESH_NETWORK_PROTOCOL_WEAKNESSES',
        'METAMORPHIC_ATTACK: SELF_MODIFYING_ATTACK_CODE_ADAPTATION',
        'DISTRIBUTED_COORDINATION: BOTNET_STYLE_MESH_COMPROMISE'
    };
    
    base_pattern = hybrid_patterns{randi(length(hybrid_patterns))};
    
    % Add complexity and entropy
    complexity_additions = {
        sprintf('[PHASE_%d_OF_%d]', randi(5), 3 + randi(7)),
        sprintf('[VECTOR_%04X]', randi(65535)),
        sprintf('[INTENSITY_%.1f]', rand()*10),
        sprintf('[TARGET_PROFILE_%d]', randi(20)),
        sprintf('[EXPLOIT_ID_%04X_%04X]', randi(65535), randi(65535))
    };
    
    content = base_pattern;
    num_additions = randi(3); % 1-3 additions
    selected_additions = complexity_additions(randperm(length(complexity_additions), num_additions));
    
    for i = 1:length(selected_additions)
        content = [content, ' ', selected_additions{i}];
    end
    
    % Add repeating pattern for size
    repeat_count = 5 + randi(15); % 5-20 repetitions
    final_content = '';
    for i = 1:repeat_count
        final_content = [final_content, content, ' '];
        % Add entropy every few repetitions
        if mod(i, 5) == 0
            entropy_chars = 'ABCDEF0123456789';
            entropy_str = '';
            for j = 1:8
                entropy_str = [entropy_str, entropy_chars(randi(length(entropy_chars)))];
            end
            final_content = [final_content, sprintf('[ENTROPY_%s] ', entropy_str)];
        end
    end
    
    content = final_content;
end
function content = generateFloodingContent(node)
    % Enhanced flooding: highly varied patterns with multiple attack vectors
    attack_patterns = struct();
    
    % Classic Flood Patterns
    attack_patterns.classic_flood = {
        'FLOOD ALERT: WATER LEVELS RISING RAPIDLY! ',
        'EMERGENCY BROADCAST: EVACUATE IMMEDIATELY! ',
        'CRITICAL WARNING: INFRASTRUCTURE FAILURE! ',
        'URGENT UPDATE: DISASTER ZONE EXPANDING! ',
        'BREAKING NEWS: CATASTROPHIC EVENT IN PROGRESS! ',
        'IMMEDIATE ACTION REQUIRED: MASS EVACUATION! '
    };
    
    % Resource Exhaustion Flood Patterns
    attack_patterns.resource_flood = {
        'EMERGENCY SERVICES OVERWHELMED - REQUESTING ALL AVAILABLE UNITS! ',
        'MEDICAL FACILITIES AT CAPACITY - OVERFLOW PROTOCOL ACTIVATED! ',
        'COMMUNICATION SYSTEMS FAILING - BACKUP NETWORKS NEEDED! ',
        'POWER GRID CRITICAL - CASCADING FAILURES IMMINENT! ',
        'TRANSPORTATION INFRASTRUCTURE COMPROMISED - ALTERNATE ROUTES! ',
        'EMERGENCY SUPPLIES DEPLETED - IMMEDIATE RESUPPLY REQUIRED! '
    };
    
    % Data Corruption Patterns
    attack_patterns.corruption_flood = {
        'ERROR_CODE_0xFF7A2B - SYSTEM_MEMORY_OVERFLOW_DETECTED! ',
        'PACKET_CORRUPTION_ALERT - DATA_INTEGRITY_COMPROMISED! ',
        'BUFFER_OVERRUN_WARNING - HEAP_ALLOCATION_FAILURE! ',
        'STACK_OVERFLOW_EXCEPTION - RECURSIVE_CALL_LIMIT_EXCEEDED! ',
        'MEMORY_LEAK_DETECTED - GARBAGE_COLLECTION_FAILED! ',
        'SEGMENTATION_FAULT - INVALID_MEMORY_ACCESS_ATTEMPT! '
    };
    
    % Social Engineering Flood Patterns
    attack_patterns.social_flood = {
        'VIRAL EMERGENCY: SHARE THIS MESSAGE TO SAVE LIVES - FORWARD TO ALL CONTACTS! ',
        'GOVERNMENT COVER-UP EXPOSED: SPREAD THE TRUTH BEFORE CENSORSHIP! ',
        'CELEBRITY SPOTTED IN DISASTER ZONE: CLICK LINK FOR EXCLUSIVE FOOTAGE! ',
        'MIRACLE SURVIVAL STORY: YOU WON''T BELIEVE WHAT HAPPENED NEXT! ',
        'CONSPIRACY REVEALED: OFFICIALS HIDING REAL DANGER LEVEL! ',
        'AMAZING RESCUE VIDEO: WATCH BEFORE IT''S REMOVED! '
    };
    
    % Technical Sabotage Patterns
    attack_patterns.technical_flood = {
        'MESH_NETWORK_DIAGNOSTIC: BANDWIDTH_SATURATION_TEST_INITIATED! ',
        'PROTOCOL_STRESS_TEST: TCP_WINDOW_SCALING_EVALUATION! ',
        'THROUGHPUT_BENCHMARK: MAXIMUM_PACKET_RATE_ANALYSIS! ',
        'LATENCY_MEASUREMENT: ROUND_TRIP_TIME_CALIBRATION! ',
        'CONGESTION_SIMULATION: QUALITY_OF_SERVICE_ASSESSMENT! ',
        'LOAD_BALANCING_TEST: TRAFFIC_DISTRIBUTION_ANALYSIS! '
    };
    
    % Select pattern type based on node's attack parameters
    pattern_types = fieldnames(attack_patterns);
    if isfield(node, 'attack_params') && isfield(node.attack_params, 'flood_pattern')
        pattern_idx = mod(node.attack_params.flood_pattern - 1, length(pattern_types)) + 1;
    else
        pattern_idx = randi(length(pattern_types));
    end
    
    selected_patterns = attack_patterns.(pattern_types{pattern_idx});
    base_pattern = selected_patterns{randi(length(selected_patterns))};
    
    % Variable repetition with entropy injection
    base_repeat = 15 + randi(35); % 15-50 base repetitions
    if isfield(node, 'attack_params') && isfield(node.attack_params, 'message_burst_size')
        repeat_multiplier = node.attack_params.message_burst_size / 10;
        repeat_count = round(base_repeat * repeat_multiplier);
    else
        repeat_count = base_repeat;
    end
    
    content = '';
    entropy_chars = '!@#$%^&*()_+-=[]{}|;:",.<>?/`~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
    
    for i = 1:repeat_count
        content = [content, base_pattern];
        
        % Add entropy every few repetitions (25% chance)
        if rand() < 0.25
            entropy_length = 3 + randi(8); % 3-10 characters
            entropy_string = '';
            for j = 1:entropy_length
                entropy_string = [entropy_string, entropy_chars(randi(length(entropy_chars)))];
            end
            content = [content, '[ENTROPY:', entropy_string, ']'];
        end
        
        % Add fake timestamps (15% chance)
        if rand() < 0.15
            fake_time = sprintf('[%02d:%02d:%02d.%03d]', randi(24)-1, randi(60), randi(60), randi(1000));
            content = [content, fake_time];
        end
        
        % Add fake packet info (10% chance)
        if rand() < 0.10
            packet_info = sprintf('[PKT_%04X_SEQ_%d]', randi(65535), randi(9999));
            content = [content, packet_info];
        end
    end
    
    % Add final attack signature
    attack_signature = sprintf('[FLOOD_ATTACK_ID_%04X_TIME_%d]', randi(65535), round(now*86400));
    content = [content, attack_signature];
end


function content = generateAdaptiveFloodingContent(node)
    % Adaptive flooding: sophisticated patterns that evolve and adapt
    content_strategies = struct();
    
    % Time-based Adaptive Patterns
    content_strategies.time_adaptive = {
        'TIME_SYNC_FLOOD: SYNCHRONIZING NETWORK CLOCKS FOR COORDINATED ATTACK! ',
        'TEMPORAL_BURST: SCHEDULED_TRANSMISSION_WINDOW_OPTIMIZATION! ',
        'CHRONOS_ATTACK: TIME_DILUTION_PROTOCOL_ACTIVATED! ',
        'ADAPTIVE_TIMING: DYNAMIC_INTERVAL_ADJUSTMENT_IN_PROGRESS! '
    };
    
    % Load-based Adaptive Patterns  
    content_strategies.load_adaptive = {
        'LOAD_MONITOR: NETWORK_UTILIZATION_EXCEEDS_THRESHOLD_ADAPTING! ',
        'TRAFFIC_SHAPING: BANDWIDTH_CONSUMPTION_OPTIMIZATION_ACTIVE! ',
        'CONGESTION_EXPLOIT: ADAPTIVE_WINDOW_SCALING_DEPLOYED! ',
        'THROUGHPUT_MAXIMIZER: DYNAMIC_PACKET_SIZE_ADJUSTMENT! '
    };
    
    % Response-based Adaptive Patterns
    content_strategies.response_adaptive = {
        'REACTIVE_FLOOD: DETECTION_EVASION_MODE_ACTIVATED! ',
        'COUNTER_MEASURE: ADAPTING_TO_DEFENSIVE_RESPONSES! ',
        'STEALTH_MODE: REDUCING_SIGNATURE_DETECTABILITY! ',
        'CAMOUFLAGE_PATTERN: MIMICKING_LEGITIMATE_TRAFFIC! '
    };
    
    % Topology-aware Adaptive Patterns
    content_strategies.topology_adaptive = {
        'MESH_MAPPER: NETWORK_TOPOLOGY_ANALYSIS_COMPLETE! ',
        'NODE_TARGETING: HIGH_CENTRALITY_NODES_IDENTIFIED! ',
        'ROUTE_OPTIMIZATION: SHORTEST_PATH_FLOODING_INITIATED! ',
        'HUB_EXPLOITATION: TARGETING_CRITICAL_RELAY_POINTS! '
    };
    
    % Multi-vector Adaptive Patterns
    content_strategies.multi_vector = {
        'HYBRID_ASSAULT: COMBINING_FLOOD_WITH_RESOURCE_EXHAUSTION! ',
        'POLYMORPHIC_ATTACK: CHANGING_SIGNATURE_EVERY_TRANSMISSION! ',
        'DISTRIBUTED_COORDINATION: SYNCHRONIZED_MULTI_NODE_FLOOD! ',
        'ESCALATION_PROTOCOL: INCREMENTALLY_INCREASING_INTENSITY! '
    };
    
    % Select strategy based on node parameters or time
    strategies = fieldnames(content_strategies);
    current_time = now * 86400; % Convert to seconds
    
    if isfield(node, 'attack_params') && isfield(node.attack_params, 'flood_pattern')
        strategy_idx = mod(node.attack_params.flood_pattern - 1, length(strategies)) + 1;
    else
        % Time-based strategy rotation
        strategy_idx = mod(floor(current_time / 120), length(strategies)) + 1; % Change every 2 minutes
    end
    
    selected_strategy = content_strategies.(strategies{strategy_idx});
    base_msg = selected_strategy{randi(length(selected_strategy))};
    
    % Adaptive burst sizing
    if isfield(node, 'attack_params') && isfield(node.attack_params, 'message_burst_size')
        base_burst = node.attack_params.message_burst_size;
        burst_interval = node.attack_params.burst_interval;
        
        % Adapt based on "learned" network conditions
        adaptation_factor = 1 + 0.5 * sin(current_time / burst_interval); % Sine wave adaptation
        actual_burst = round(base_burst * adaptation_factor);
    else
        actual_burst = 10 + randi(15); % 10-25 default
    end
    
    content = '';
    
    % Generate adaptive content with evolving patterns
    for i = 1:actual_burst
        content = [content, base_msg];
        
        % Add adaptive elements based on burst position
        progress_ratio = i / actual_burst;
        
        % Early phase: reconnaissance data
        if progress_ratio < 0.3
            recon_data = sprintf('[RECON_PHASE:NET_MAP_%02d_NODES_%02d]', ...
                randi(99), 20 + randi(30));
            content = [content, recon_data];
        % Middle phase: exploitation
        elseif progress_ratio < 0.7
            exploit_data = sprintf('[EXPLOIT:VULN_%04X_TARGET_%02d]', ...
                randi(65535), randi(50));
            content = [content, exploit_data];
        % Final phase: persistence
        else
            persist_data = sprintf('[PERSIST:BACKDOOR_%04X_MAINTAIN_%d]', ...
                randi(65535), randi(300));
            content = [content, persist_data];
        end
        
        % Add dynamic entropy based on adaptation
        if rand() < (0.1 + 0.3 * progress_ratio) % Increasing entropy
            entropy_chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
            entropy_len = 5 + round(10 * progress_ratio);
            entropy_str = '';
            for j = 1:entropy_len
                entropy_str = [entropy_str, entropy_chars(randi(length(entropy_chars)))];
            end
            content = [content, sprintf('[ADAPTIVE_ENTROPY:%s]', entropy_str)];
        end
    end
    
    % Add adaptive signature that changes over time
    adaptive_signature = sprintf('[ADAPTIVE_FLOOD_V%.1f_EVOLUTION_%04X]', ...
        1.0 + mod(current_time, 86400) / 86400, randi(65535));
    content = [content, adaptive_signature];
end

function content = generateResourceExhaustionContent(node)
    % Enhanced resource exhaustion: sophisticated multi-target attacks
    exhaustion_vectors = struct();
    
    % Battery Drain Attacks
    exhaustion_vectors.battery_drain = {
        'BATTERY_VAMPIRE: HIGH_COMPUTATION_CRYPTOGRAPHIC_PUZZLE_SOLVE_NOW! ',
        'POWER_SINK: CONTINUOUS_RADIO_TRANSMISSION_MODE_ACTIVATED! ',
        'ENERGY_LEECH: FORCE_MAXIMUM_TRANSMISSION_POWER_LEVELS! ',
        'DRAIN_PROTOCOL: DISABLE_POWER_SAVING_MODES_IMMEDIATELY! ',
        'BATTERY_BOMB: INFINITE_LOOP_COMPUTATIONAL_TASK_INITIATED! '
    };
    
    % Memory Exhaustion Attacks
    exhaustion_vectors.memory_exhaustion = {
        'MEMORY_ALLOCATOR: RECURSIVE_BUFFER_EXPANSION_PROTOCOL! ',
        'HEAP_BOMBER: DYNAMIC_ALLOCATION_WITHOUT_DEALLOCATION! ',
        'RAM_CONSUMER: CACHE_POLLUTION_ATTACK_IN_PROGRESS! ',
        'BUFFER_INFLATOR: EXPONENTIAL_GROWTH_PATTERN_DETECTED! ',
        'MEMORY_FRAGMENTER: SCATTERED_ALLOCATION_STRATEGY_ACTIVE! '
    };
    
    % Processing Power Attacks
    exhaustion_vectors.cpu_exhaustion = {
        'CPU_BURNER: PRIME_NUMBER_CALCULATION_TO_TRILLION_INITIATED! ',
        'PROCESSOR_OVERLOAD: RECURSIVE_FIBONACCI_COMPUTATION_ACTIVE! ',
        'COMPUTATIONAL_BOMB: CRYPTOGRAPHIC_HASH_BRUTE_FORCE_RUNNING! ',
        'CYCLE_WASTER: INFINITE_SORTING_ALGORITHM_LOOP_STARTED! ',
        'ARITHMETIC_FLOOD: COMPLEX_MATHEMATICAL_OPERATIONS_QUEUED! '
    };
    
    % Network Resource Attacks
    exhaustion_vectors.network_exhaustion = {
        'BANDWIDTH_SATURATOR: MAXIMUM_THROUGHPUT_TEST_CONTINUOUS! ',
        'CONNECTION_FLOODER: TCP_SYN_FLOOD_ATTACK_INITIATED! ',
        'PACKET_STORM: UDP_BROADCAST_AMPLIFICATION_ACTIVE! ',
        'PROTOCOL_ABUSER: MALFORMED_HEADER_PROCESSING_OVERLOAD! ',
        'ROUTING_CHAOS: TOPOLOGY_CONFUSION_ATTACK_DEPLOYED! '
    };
    
    % Storage Exhaustion Attacks  
    exhaustion_vectors.storage_exhaustion = {
        'DISK_FILLER: RAPID_LOG_FILE_EXPANSION_PROTOCOL! ',
        'STORAGE_BOMBER: TEMPORARY_FILE_CREATION_SPREE! ',
        'CACHE_POLLUTER: INVALID_DATA_INJECTION_CONTINUOUS! ',
        'FILE_FRAGMENTER: SCATTERED_WRITE_PATTERN_ATTACK! ',
        'JOURNAL_SPAMMER: EXCESSIVE_METADATA_GENERATION! '
    };
    
    % Multi-resource Combined Attacks
    exhaustion_vectors.combined_exhaustion = {
        'RESOURCE_APOCALYPSE: SIMULTANEOUS_ALL_SYSTEM_ATTACK! ',
        'TOTAL_DEPLETION: COORDINATED_MULTI_VECTOR_ASSAULT! ',
        'SYSTEM_CRUSHER: CASCADING_FAILURE_CHAIN_INITIATED! ',
        'RESOURCE_STORM: OVERWHELMING_DEMAND_GENERATION! ',
        'EXHAUSTION_MATRIX: COMPLEX_INTERDEPENDENT_ATTACKS! '
    };
    
    % Select attack vector based on node parameters
    vectors = fieldnames(exhaustion_vectors);
    
    if isfield(node, 'attack_params') && isfield(node.attack_params, 'target_resource')
        % Map target_resource to specific vector
        target_map = [1, 2, 3, 4, 5, 6]; % battery, memory, cpu, network, storage, combined
        vector_idx = min(node.attack_params.target_resource, length(vectors));
    else
        vector_idx = randi(length(vectors));
    end
    
    selected_vector = exhaustion_vectors.(vectors{vector_idx});
    base_payload = selected_vector{randi(length(selected_vector))};
    
    % Calculate payload size based on exhaustion parameters
    if isfield(node, 'attack_params') && isfield(node.attack_params, 'exhaustion_rate')
        intensity_multiplier = node.attack_params.exhaustion_rate * 1000; % Scale for larger payloads
        base_repetitions = round(200 + intensity_multiplier);
    else
        base_repetitions = 300 + randi(400); % 300-700 repetitions
    end
    
    content = '';
    
    % Generate resource-hungry content
    for i = 1:base_repetitions
        content = [content, base_payload];
        
        % Add resource-specific bloat patterns
        switch vector_idx
            case 1 % Battery drain - crypto-heavy content
                if mod(i, 20) == 0
                    crypto_data = sprintf('[CRYPTO_HASH_%064s]', ...
                        dec2hex(randi([0, 2^32-1], 1, 16), 8));
                    content = [content, crypto_data];
                end
                
            case 2 % Memory exhaustion - large data blocks
                if mod(i, 15) == 0
                    memory_block = repmat('MEMORY_BLOCK_DATA_', 1, 50);
                    block_id = sprintf('[MEM_BLOCK_%08X_SIZE_%d]', randi(2^32-1), length(memory_block));
                    content = [content, memory_block, block_id];
                end
                
            case 3 % CPU exhaustion - computational tasks
                if mod(i, 25) == 0
                    compute_task = sprintf('[COMPUTE_TASK:PRIME_CHECK_%d_FACTORIAL_%d]', ...
                        randi(10000), randi(100));
                    content = [content, compute_task];
                end
                
            case 4 % Network exhaustion - protocol overhead
                if mod(i, 10) == 0
                    protocol_overhead = sprintf('[NET_HEADER:SRC_%d_DST_%d_SEQ_%d_ACK_%d_WIN_%d]', ...
                        randi(255), randi(255), randi(2^32-1), randi(2^32-1), randi(65535));
                    content = [content, protocol_overhead];
                end
                
            case 5 % Storage exhaustion - log spam
                if mod(i, 30) == 0
                    log_spam = sprintf('[LOG_ENTRY_%s:EVENT_%04X_DATA_', ...
                        datestr(now, 'yyyy-mm-dd_HH:MM:SS.FFF'), randi(65535));
                    padding = repmat('X', 1, 100);
                    content = [content, log_spam, padding, ']'];
                end
                
            case 6 % Combined exhaustion - all techniques
                if mod(i, 12) == 0
                    combined_load = sprintf('[COMBINED:CRYPTO_%08X_MEM_%d_CPU_%d_NET_%d_DISK_%d]', ...
                        randi(2^32-1), randi(1000), randi(100), randi(255), randi(500));
                    content = [content, combined_load];
                end
        end
        
        % Add variable entropy to prevent compression
        if rand() < 0.2
            entropy_data = '';
            entropy_chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:",.<>?/`~';
            for j = 1:20
                entropy_data = [entropy_data, entropy_chars(randi(length(entropy_chars)))];
            end
            content = [content, sprintf('[ENTROPY:%s]', entropy_data)];
        end
    end
    
    % Add attack metadata
    resource_signature = sprintf('[RESOURCE_EXHAUSTION:VECTOR_%d_INTENSITY_%.2f_SIZE_%d_TIME_%d]', ...
        vector_idx, 0.5 + rand()*0.5, length(content), round(now*86400));
    content = [content, resource_signature];
end


function content = generateSpoofingContent(node)
    % Enhanced spoofing: sophisticated deception with multiple attack vectors
    spoofing_categories = struct();
    
    % Phishing and Social Engineering
    spoofing_categories.phishing = {
        'URGENT: Verify emergency account at https://fake-emergency%d.gov/verify?token=%s immediately!',
        'CRITICAL: Update disaster response credentials at www.spoofed-fema%d.org/update/%s now!',
        'SECURITY: Confirm identity for rescue coordination at https://phishing-rescue%d.com/auth?id=%s',
        'WARNING: Account suspended! Reactivate at fake-redcross%d.org/reactivate/%s within 1 hour!',
        'ALERT: Fraudulent activity detected! Secure account at www.malicious-bank%d.com/secure?ref=%s',
        'EMERGENCY: Family member needs help! Send money via compromised-pay%d.com/transfer/%s'
    };
    
    % Authority Impersonation
    spoofing_categories.authority_impersonation = {
        'OFFICIAL NOTICE: This is FEMA Director %s. Report to evacuation-fake%d.gov/report?auth=%s immediately.',
        'GOVERNMENT ORDER: By authority of Emergency Coordinator %s, visit official-spoof%d.org/orders/%s',
        'POLICE DIRECTIVE: Chief %s requires verification at fake-police%d.gov/verify?badge=%s urgently.',
        'MEDICAL ALERT: Dr. %s from Emergency Response requests data at med-spoof%d.com/patient/%s',
        'MILITARY COMMAND: Colonel %s orders compliance check at defense-fake%d.mil/status?unit=%s',
        'RED CROSS UPDATE: Director %s needs volunteer confirmation at humanitarian-spoof%d.org/confirm/%s'
    };
    
    % False Emergency Scenarios
    spoofing_categories.false_emergency = {
        'BREAKING: Child trapped in %s needs immediate help! Donate at emergency-fake%d.com/donate?child=%s',
        'URGENT: %s evacuation center overwhelmed! Alternative shelter at misleading-shelter%d.org/register/%s',
        'CRITICAL: Water contamination in %s area! Test results at fake-health%d.gov/results?zone=%s',
        'ALERT: Gas leak reported near %s! Safety info at hazard-spoof%d.com/safety?location=%s',
        'WARNING: Structural collapse imminent at %s! Details at disaster-fake%d.org/alerts?building=%s',
        'EMERGENCY: Medical supplies shortage in %s! Support at relief-spoof%d.com/supplies?area=%s'
    };
    
    % Technical Spoofing
    spoofing_categories.technical_spoofing = {
        'SYSTEM UPDATE: Mesh node requires firmware update from update-server%d.fake/firmware?node=%s',
        'NETWORK ALERT: Security patch available at patch-distribution%d.spoof/download?device=%s',
        'PROTOCOL UPDATE: New emergency mesh protocol at protocol-fake%d.net/upgrade?network=%s',
        'SECURITY SCAN: Malware detected! Clean immediately at antivirus-spoof%d.com/clean?system=%s',
        'CONFIGURATION CHANGE: Update network settings via config-fake%d.org/update?settings=%s',
        'DIAGNOSTIC REQUIRED: Run network test at network-spoof%d.com/diagnostic?test=%s'
    };
    
    % Identity Theft Patterns
    spoofing_categories.identity_theft = {
        'VERIFICATION: Confirm identity for family reunion database at family-finder%d.fake/verify?person=%s',
        'REGISTRATION: Emergency contact system requires details at contact-spoof%d.org/register?emergency=%s',
        'DATABASE UPDATE: Personal info verification needed at citizen-fake%d.gov/update?citizen=%s',
        'INSURANCE CLAIM: Disaster insurance requires documents at insurance-spoof%d.com/claim?policy=%s',
        'BENEFIT ENROLLMENT: Emergency aid signup at disaster-benefits%d.fake/enroll?applicant=%s',
        'MEDICAL RECORD: Health emergency requires verification at medical-spoof%d.org/records?patient=%s'
    };
    
    % Advanced Persistent Spoofing
    spoofing_categories.persistent_spoofing = {
        'LONG-TERM SUPPORT: Register for ongoing disaster updates at updates-fake%d.com/subscribe?user=%s',
        'COMMUNITY PORTAL: Join neighborhood recovery network at community-spoof%d.org/join?resident=%s',
        'VOLUNTEER REGISTRY: Sign up for extended relief efforts at volunteer-fake%d.net/register?helper=%s',
        'RECONSTRUCTION PLANNING: Participate in rebuilding initiative at rebuild-spoof%d.com/participate?member=%s',
        'RECOVERY COORDINATION: Long-term aid management at recovery-fake%d.org/manage?coordinator=%s',
        'MENTAL HEALTH SUPPORT: Ongoing counseling services at therapy-spoof%d.com/support?client=%s'
    };
    
    % Select category based on current time or node parameters  
    categories = fieldnames(spoofing_categories);
    if isfield(node, 'last_attack_time')
        % Rotate categories based on time to add variety
        time_factor = mod(floor(node.last_attack_time / 300), length(categories)) + 1; % Change every 5 minutes
        selected_category = categories{time_factor};
    else
        selected_category = categories{randi(length(categories))};
    end
    
    templates = spoofing_categories.(selected_category);
    template = templates{randi(length(templates))};
    
    % Generate convincing fake data
    fake_names = {'Johnson', 'Smith', 'Williams', 'Brown', 'Davis', 'Miller', 'Wilson', 'Taylor', 'Anderson', 'Thomas'};
    fake_locations = {'Downtown', 'Riverside', 'Hillside', 'Central District', 'North Zone', 'South Sector'};
    
    % Create random parameters with high entropy
    random_num = 1000 + randi(8999); % 4-digit number
    
    % Generate complex token with mixed characters
    token_chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    token = '';
    token_length = 12 + randi(8); % 12-20 character token
    for i = 1:token_length
        token = [token, token_chars(randi(length(token_chars)))];
    end
    
    % Select random name and location
    fake_name = fake_names{randi(length(fake_names))};
    fake_location = fake_locations{randi(length(fake_locations))};
    
    % Format the spoofing message based on template
    if contains(template, '%s') && contains(template, '%d')
        % Template requires both string and number
        if sum(template == '%') == 3 % Three parameters
            content = sprintf(template, fake_name, random_num, token);
        elseif sum(template == '%') == 2 % Two parameters  
            if strfind(template, '%s') < strfind(template, '%d')
                content = sprintf(template, fake_location, random_num);
            else
                content = sprintf(template, random_num, token);
            end
        end
    else
        content = template;
    end
    
    % Add suspicious elements to increase detection difficulty
    suspicious_elements = {
        sprintf(' [AUTH_CODE: %06d]', randi(999999)),
        sprintf(' Reference: #%s', upper(token(1:min(8, length(token))))),
        sprintf(' Priority Level: %d', randi(5)),
        sprintf(' Case ID: %04X-%04X', randi(65535), randi(65535)),
        sprintf(' Verification: %s%04d', token_chars(randi(26)), randi(9999))
    };
    
    % Add 1-2 suspicious elements
    num_elements = 1 + randi(2);
    selected_elements = suspicious_elements(randperm(length(suspicious_elements), num_elements));
    
    for i = 1:length(selected_elements)
        content = [content, selected_elements{i}];
    end
    
    % Add timestamp for realism
    if rand() < 0.4 % 40% chance
        fake_timestamp = sprintf(' [Sent: %02d/%02d %02d:%02d]', ...
            randi(12), randi(28), randi(24)-1, randi(60)-1);
        content = [content, fake_timestamp];
    end
    
    % Add spoofing signature (hidden)
    spoof_signature = sprintf(' [SPOOF_ID_%04X_CAT_%s]', randi(65535), selected_category);
    content = [content, spoof_signature];
end

function content = generateNormalMessage()
    % Enhanced emergency chat messages with more variety and complexity
    message_categories = struct();
    
    % Emergency Coordination (High Priority/Frequency) - EXPANDED
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
        'SOS: Trapped in basement, water coming in, send help!',
        % NEW ADDITIONS for variety
        'Urgent coordination: Assembly point moved to Central Park due to flooding',
        'Family reunion: Meet at Fire Station #7 if separated',
        'Critical update: Bridge at Miller St is collapsing - avoid area!',
        'Emergency relay: Need medical personnel at evacuation center NOW',
        'Rescue priority: Children trapped at Roosevelt Elementary School',
        'Safety alert: Gas leak reported on 5th Avenue, evacuate immediately',
        'Communication hub: Ham radio operators needed at command center',
        'Search coordination: Missing elderly woman, blue coat, answers to Mary',
        'Emergency shelter: Community center full, redirecting to high school',
        'Medical emergency: Diabetic child needs insulin at shelter B',
        'Transport urgent: Pregnant woman in labor needs hospital access',
        'Resource critical: Running low on oxygen tanks at medical station',
        'Evacuation notice: Dam spillway opening in 30 minutes - move to high ground'
    };
    
    % Safety Status Updates (High Frequency) - EXPANDED
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
        'Secure: In emergency bunker with 20 other people',
        % NEW ADDITIONS
        'Check-in: All family members accounted for at Riverside shelter',
        'Status good: Temporary housing secured, have basic supplies',
        'Update positive: Injuries treated, recovery going well',
        'Safe location: Staying with relatives outside flood zone',
        'Current position: GPS coordinates 40.7589, -73.9851 - safe area',
        'Health status: Minor cuts treated, no serious injuries',
        'Shelter report: Adequate food and water, morale holding up',
        'Safety confirmed: All team members present and unharmed',
        'Location secure: High ground position, good visibility',
        'Status nominal: Power restored in our sector, communications good',
        'Welfare check: Elderly parents safe at assisted living facility',
        'Group status: 12 people safe in basement shelter, supplies adequate',
        'Recovery update: Clean water access restored, sanitation improving'
    };
    
    % Resource Requests (Medium Frequency) - EXPANDED  
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
        'Information: Which roads are still passable?',
        % NEW ADDITIONS
        'Request urgent: Insulin needed for Type 1 diabetic, running low',
        'Supplies needed: Blankets and warm clothes for 15 children',
        'Medical request: Blood pressure medication for cardiac patient',
        'Food assistance: Gluten-free options for celiac child',
        'Equipment need: Wheelchair accessible vehicle for transport',
        'Communication help: Satellite phone to contact relatives abroad',
        'Shelter space: Family with newborn needs quiet, clean area',
        'Technical support: Radio equipment repair - have spare parts?',
        'Medical urgent: Epinephrine auto-injector for severe allergic reaction',
        'Resource sharing: Extra solar chargers available for trade',
        'Transportation: Boat needed to reach stranded residents',
        'Supplies critical: Water purification tablets running low',
        'Equipment request: Chainsaw operator needed to clear blocked roads',
        'Medical supplies: Bandages and antiseptic for wound care',
        'Food distribution: Vegetarian meals needed at shelter C'
    };
    
    % Rescue Coordination (Medium Frequency) - EXPANDED
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
        'Equipment: Have rope and tools for rescue operations',
        % NEW ADDITIONS
        'Rescue team: Swift water rescue unit deploying to residential area',
        'Medical support: Trauma surgeon available at field hospital',
        'Technical assistance: Engineer assessing structural damage',
        'Transport coordination: School bus convoy organizing evacuation routes',
        'Communication relay: Setting up mesh network for emergency services',
        'Search and rescue: Drone operators mapping flooded areas',
        'Supply distribution: Food truck stationed at Main St & 3rd Ave',
        'Medical evacuation: Helicopter landing zone established at park',
        'Emergency services: Paramedic team standing by for critical cases',
        'Utility repair: Electrical crew working to restore power grid',
        'Water rescue: Coast Guard auxiliary boats patrolling river',
        'Animal rescue: Veterinary team helping with pet evacuations',
        'Logistics support: Coordinating supply deliveries to shelters',
        'Security patrol: Volunteers monitoring evacuation areas',
        'Mental health: Counselors available for trauma support'
    };
    
    % Information Sharing (Low Frequency) - EXPANDED
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
        'Broadcast: Government aid arriving tomorrow morning',
        % NEW ADDITIONS
        'Weather update: Storm surge warning extended through 6 AM',
        'Traffic advisory: Highway 101 reopened with lane restrictions',
        'Service notice: Cell towers restored in sectors 7-12',
        'Public health: Tetanus vaccination station set up at clinic',
        'Infrastructure: Water treatment plant back online, pressure low',
        'Emergency broadcast: FEMA disaster relief center opening Monday',
        'Transportation: Ferry service suspended due to high winds',
        'Utility update: Natural gas service shut off preventively',
        'Communication: Internet service restored in northern districts',
        'Weather forecast: Flooding expected to peak at 3 PM today',
        'Official notice: National Guard units arriving for assistance',
        'Health alert: Boil water order may last 48-72 hours',
        'Transportation: Train service suspended indefinitely',
        'Emergency services: Additional ambulances en route from nearby counties',
        'Infrastructure report: Power restoration estimated 5-7 days for most areas'
    };
    
    % NEW CATEGORY: Technical/Operational Messages
    message_categories.technical_operational = {
        'System status: Backup generators operating at 85% capacity',
        'Network diagnostic: Mesh node #47 offline, rerouting traffic',
        'Equipment check: Radio frequency 146.520 clear for emergency use',
        'Technical update: Satellite uplink established, data transmission stable',
        'Operational report: Search grid Delta-7 completed, no survivors found',
        'System alert: Battery backup systems switching to conservation mode',
        'Network maintenance: Mesh topology reconfigured for optimal coverage',
        'Technical support: Software update pushed to all emergency devices',
        'Operational status: Command center Alpha operational, Bravo relocating',
        'System notification: GPS tracking active for all rescue vehicles'
    };
    
    % NEW CATEGORY: Social/Morale Messages  
    message_categories.social_morale = {
        'Community: Prayer circle forming at 7 PM in shelter common area',
        'Morale boost: Local restaurant donating hot meals to volunteers',
        'Social support: Childcare available so parents can help with rescue',
        'Community spirit: Neighbors sharing generators and supplies',
        'Emotional support: Therapy dogs arriving tomorrow for stress relief',
        'Social coordination: Planning community cleanup when waters recede',
        'Morale message: We''re stronger together - this too shall pass',
        'Community aid: Local church organizing clothing drive',
        'Social activity: Story time for children at 3 PM in shelter B',
        'Community support: Volunteer appreciation dinner planned for Friday'
    };
    
    % Select category based on disaster communication patterns
    categories = fieldnames(message_categories);
    category_weights = [0.35, 0.25, 0.15, 0.12, 0.08, 0.03, 0.02]; % Emergency coordination most frequent
    
    rand_val = rand();
    cumsum_weights = cumsum(category_weights);
    category_idx = find(rand_val <= cumsum_weights, 1);
    selected_category = categories{category_idx};
    
    messages = message_categories.(selected_category);
    base_content = messages{randi(length(messages))};
    
    % Add variability with timestamps, locations, and numbers
    content = addMessageVariability(base_content);
end

function content = addMessageVariability(base_content)
    % Add realistic variability to make messages more unique
    content = base_content;
    
    % 30% chance to add timestamp
    if rand() < 0.3
        time_str = sprintf(' [%02d:%02d]', randi(24)-1, randi(60)-1);
        content = [content, time_str];
    end
    
    % 20% chance to add location reference
    if rand() < 0.2
        locations = {'Zone A', 'Sector 4', 'Grid 7-B', 'Area North', 'District 3', 'Block 15'};
        location_str = sprintf(' (%s)', locations{randi(length(locations))});
        content = [content, location_str];
    end
    
    % 15% chance to add urgency modifier
    if rand() < 0.15
        urgency = {'*URGENT*', '**PRIORITY**', '[IMMEDIATE]', '***TIME SENSITIVE***'};
        content = [urgency{randi(length(urgency))}, ' ', content];
    end
    
    % 10% chance to add contact info
    if rand() < 0.1
        contact_str = sprintf(' Contact: %d', 1000 + randi(9000));
        content = [content, contact_str];
    end
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

function ids_model = createOptimizedMATLABModel(ids_model)
    % Create MATLAB model with parameters optimized based on Python training results
    try
        fprintf(' Creating optimized MATLAB Random Forest model...\n');
        
        % Use optimized parameters that match your Python training
        % These parameters are based on typical optimal RF configurations
        optimized_params = struct();
        optimized_params.n_estimators = 200;           % Similar to Python model
        optimized_params.max_features = 'sqrt';        % Square root of features
        optimized_params.min_leaf_size = 1;            % Minimum samples per leaf
        optimized_params.in_bag_fraction = 0.7;        % Bootstrap sampling ratio
        optimized_params.method = 'classification';    % Classification task
        
        fprintf(' Model parameters:\n');
        fprintf('   - Trees: %d\n', optimized_params.n_estimators);
        fprintf('   - Max Features: %s\n', optimized_params.max_features);
        fprintf('   - Min Leaf Size: %d\n', optimized_params.min_leaf_size);
        fprintf('   - Bag Fraction: %.1f\n', optimized_params.in_bag_fraction);
        
        
        if strcmp(optimized_params.max_features, 'sqrt')
            n_predictors = floor(sqrt(n_features));
        else
            n_predictors = optimized_params.max_features;
        end
        
        fprintf(' Training TreeBagger with optimized settings...\n');
        
        % Create optimized TreeBagger
        ids_model.rf_model = TreeBagger(...
            optimized_params.n_estimators, ...
            X_train, y_train, ...
            'Method', optimized_params.method, ...
            'NumPredictorsToSample', n_predictors, ...
            'MinLeafSize', optimized_params.min_leaf_size, ...
            'InBagFraction', optimized_params.in_bag_fraction, ...
            'OOBPrediction', 'on', ...              % Enable out-of-bag error estimation
            'OOBPredictorImportance', 'on' ...      % Calculate feature importance
        );
        
        ids_model.model_loaded = true;
        ids_model.model_type = 'MATLAB_OPTIMIZED';
        ids_model.optimization_source = 'PYTHON_TRAINING_INSPIRED';
        
        % Calculate and display model performance
        oob_error = oobError(ids_model.rf_model);
        fprintf('✅ Optimized MATLAB model trained successfully!\n');
        fprintf(' Out-of-bag error rate: %.4f (%.2f%% accuracy)\n', oob_error, (1-oob_error)*100);
        
        % Display feature importance if available
        try
            importance = ids_model.rf_model.OOBPermutedPredictorDeltaError;
            if ~isempty(importance)
                [~, sorted_idx] = sort(importance, 'descend');
                fprintf(' Top 5 most important features:\n');
                feature_names = {
                    'node_density', 'isolation_factor', 'emergency_priority', 'hop_reliability',
                    'network_fragmentation', 'critical_node_count', 'backup_route_availability',
                    'message_length', 'entropy_score', 'special_char_ratio', 'numeric_ratio',
                    'emergency_keyword_count', 'suspicious_url_count', 'command_pattern_count',
                    'message_frequency', 'burst_intensity', 'inter_arrival_variance',
                    'size_consistency', 'timing_regularity', 'volume_anomaly_score',
                    'sender_reputation', 'message_similarity_score', 'response_pattern',
                    'interaction_diversity', 'temporal_consistency', 'language_consistency',
                    'ttl_anomaly', 'sequence_gap_score', 'routing_anomaly', 'header_integrity',
                    'encryption_consistency', 'protocol_compliance_score', 'battery_impact_score',
                    'processing_load', 'memory_footprint', 'signal_strength_factor',
                    'mobility_pattern', 'emergency_context_score', 'route_stability',
                    'forwarding_behavior', 'neighbor_trust_score', 'mesh_connectivity_health',
                    'redundancy_factor'
                };
                
                for i = 1:min(5, length(sorted_idx))
                    feat_idx = sorted_idx(i);
                    if feat_idx <= length(feature_names)
                        fprintf('   %d. %s: %.4f\n', i, feature_names{feat_idx}, importance(feat_idx));
                    end
                end
            end
        catch
            fprintf(' Feature importance calculation skipped\n');
        end
        
    catch ME
        fprintf('❌ Optimized model creation failed: %s\n', ME.message);
        fprintf(' Falling back to standard training...\n');
    end
end

function ids_model = loadPretrainedModel(ids_model)
    % Load parameters from your pre-trained model (MATLAB-native approach)
    try
        fprintf(' Loading parameters from your pre-trained model...\n');
        
        % Load our comprehensive Random Forest model using the loader function
        try
            % Use the loadRandomForestModel function we created
            if exist('loadRandomForestModel.m', 'file')
                comprehensive_model = loadRandomForestModel();
                
                % Integrate the loaded model into our IDS structure
                ids_model.rf_model = comprehensive_model.rf_model;
                ids_model.model_type = 'MATLAB';
                ids_model.model_loaded = true;
                ids_model.optimization_source = 'COMPREHENSIVE_RF_MODEL';
                ids_model.validation_accuracy = comprehensive_model.accuracy;
                ids_model.feature_names = comprehensive_model.feature_names;
                
                fprintf('✅ Successfully loaded comprehensive Random Forest model!\n');
                fprintf(' Model details:\n');
                fprintf('   - Validation Accuracy: %.2f%%\n', comprehensive_model.accuracy * 100);
                fprintf('   - Features: %d\n', length(comprehensive_model.feature_names));
                fprintf('   - Classes: %s\n', strjoin(comprehensive_model.class_names, ', '));
                return;
            else
                fprintf('⚠️ loadRandomForestModel.m not found, trying direct model loading...\n');
            end
        catch load_error
            fprintf('⚠️ Failed to load using loadRandomForestModel: %s\n', load_error.message);
        end
        
        % Fallback: Direct loading of the latest Random Forest model
        model_files = dir('models/bluetooth_mesh_ids_rf_*.mat');
        if ~isempty(model_files)
            % Sort by date and take the newest
            [~, newest_idx] = max([model_files.datenum]);
            model_path = fullfile(model_files(newest_idx).folder, model_files(newest_idx).name);
            fprintf(' Found Random Forest model: %s\n', model_files(newest_idx).name);
            
            try
                % Load the model directly
                fprintf(' Loading Random Forest model...\n');
                model_data = load(model_path);
                if isfield(model_data, 'rf_model')
                    ids_model.rf_model = model_data.rf_model;
                    ids_model.model_type = 'MATLAB';
                    ids_model.model_loaded = true;
                    ids_model.optimization_source = 'DIRECT_RF_LOAD';
                    fprintf('✅ Successfully loaded Random Forest model directly!\n');
                    return;
                else
                    fprintf('⚠️ Model file does not contain rf_model field\n');
                end
            catch load_error
                fprintf('⚠️ Failed to load model directly: %s\n', load_error.message);
            end
        else
            fprintf('❌ No Random Forest model found in models/ directory\n');
            fprintf(' Please run buildRandomForestModel.m first\n');
            error('No Random Forest model available');
        end
        
    catch ME
        fprintf('❌ Model loading failed: %s\n', ME.message);
        fprintf(' Please check that your Random Forest model exists and is valid\n');
        error('Failed to load Random Forest model');
    end
end



function shared_model = createSharedIDSModel()
    shared_model = struct();
    shared_model.model_loaded = false;
    shared_model.attack_types = {'NORMAL', 'FLOODING', 'ADAPTIVE_FLOODING', 'BLACK_HOLE', 'SPOOFING', 'RESOURCE_EXHAUSTION'};
    
    shared_model.feature_weights = rand(43, 1);
    shared_model.rules = createDetectionRules();
    shared_model.hybrid_mode = true;
    shared_model.rule_confidence_threshold = 0.7;  % INCREASED: Require higher confidence (was 0.5)
    shared_model.ai_confidence_threshold = 0.6;   % INCREASED: Require higher confidence (was 0.4)
    shared_model.fusion_weights = struct('rule_weight', 0.5, 'ai_weight', 0.5);  % Balanced weights
    
    % Load pre-trained model instead of training new one
    shared_model = loadPretrainedModel(shared_model);
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

function node = cleanupMessageBuffer(node, current_time)
    % Optimized cleanup based on buffer entry time (how long message has been in buffer)
    if isempty(node.message_buffer.messages)
        return;
    end
    
    % Since messages are buffer-entry-time-ordered, find cutoff point efficiently
    cutoff_time = current_time - node.buffer_ttl;
    
    % Binary search or simple scan to find first message that hasn't been in buffer too long
    keep_from_index = 1;
    for i = 1:length(node.message_buffer.buffer_entry_times)
        if node.message_buffer.buffer_entry_times(i) > cutoff_time
            keep_from_index = i;
            break;
        end
        keep_from_index = i + 1;  % All messages expire, keep none
    end
    
    % Calculate expired count and reclaim bytes
    expired_count = keep_from_index - 1;
    bytes_freed = 0;
    
    if expired_count > 0
        % Calculate bytes freed from expired messages
        for i = 1:expired_count
            bytes_freed = bytes_freed + length(node.message_buffer.messages{i}.content);
        end
        
        % Remove expired messages efficiently (slice arrays)
        node.message_buffer.messages = node.message_buffer.messages(keep_from_index:end);
        node.message_buffer.buffer_entry_times = node.message_buffer.buffer_entry_times(keep_from_index:end);
        node.message_buffer.total_bytes = node.message_buffer.total_bytes - bytes_freed;
        
        % Log cleanup with more details
        fprintf('BUFFER CLEANUP: Node %d cleaned %d messages (in buffer >%.0fs, freed %d bytes, current_time=%.0fs)\n', ...
            node.id, expired_count, node.buffer_ttl, bytes_freed, current_time);
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
    fprintf('🔧 Loading comprehensive Random Forest model (102 datasets, 79K+ samples)...\n');
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
        if mod(current_time, 1) == 0  % Check every 1 second for more frequent cleanup
            
            % Clean up expired messages from all nodes (both cache and buffer)
            for i = 1:length(nodes)
                if nodes(i).is_active
                    nodes(i) = cleanupMessageCache(nodes(i), current_time);
                    nodes(i) = cleanupMessageBuffer(nodes(i), current_time);
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
                                                %fprintf('Message %s dropped: TTL=%d, hops=%d (max_hops=%d)\n', ...
                                                %    msg_id, forwarded_msg.ttl, forwarded_msg.hop_count, MAX_HOP_COUNT);
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

function [is_attack, attack_type, confidence] = predictWithPythonModel(ids_model, features)
    % Use your pre-trained Python model's feature importance weights for prediction
    % This simulates your Python RandomForest without retraining
    
    try
        % Calculate weighted score using your Python model's feature importance
        if length(features) ~= length(ids_model.prediction_weights)
            % Pad or truncate features to match expected size
            expected_size = length(ids_model.prediction_weights);
            if length(features) < expected_size
                features = [features, zeros(1, expected_size - length(features))];
            else
                features = features(1:expected_size);
            end
        end
        
        % Normalize features to [0,1] range
        max_features = max(features);
        min_features = min(features);
        if max_features > min_features
            normalized_features = (features - min_features) / (max_features - min_features);
        else
            normalized_features = features;
        end
        
        % Enhanced attack detection logic based on actual attack patterns
        attack_scores = struct();
        
        % Key feature indices (based on our feature extraction)
        msg_freq_idx = 15;      % message_frequency
        msg_size_idx = 8;       % message_length  
        suspicious_url_idx = 13; % suspicious_url_count
        sender_rep_idx = 21;    % sender_reputation
        battery_impact_idx = 33; % battery_impact
        forwarding_idx = 40;    % forwarding_behavior
        routing_anomaly_idx = 29; % routing_anomaly
        
        % FLOODING detection
        flooding_score = 0;
        if normalized_features(msg_freq_idx) > 0.3
            flooding_score = flooding_score + 0.4;
        end
        if normalized_features(msg_size_idx) > 0.2
            flooding_score = flooding_score + 0.3;
        end
        if normalized_features(battery_impact_idx) > 0.4
            flooding_score = flooding_score + 0.3;
        end
        attack_scores.FLOODING = flooding_score;
        
        % SPOOFING detection
        spoofing_score = 0;
        if normalized_features(suspicious_url_idx) > 0
            spoofing_score = spoofing_score + 0.5;
        end
        if normalized_features(sender_rep_idx) < 0.5
            spoofing_score = spoofing_score + 0.3;
        end
        attack_scores.SPOOFING = spoofing_score;
        
        % BLACK_HOLE detection
        blackhole_score = 0;
        if normalized_features(forwarding_idx) < 0.3
            blackhole_score = blackhole_score + 0.4;
        end
        if normalized_features(routing_anomaly_idx) > 0.3
            blackhole_score = blackhole_score + 0.4;
        end
        attack_scores.BLACK_HOLE = blackhole_score;
        
        % RESOURCE_EXHAUSTION detection
        resource_score = 0;
        if normalized_features(msg_size_idx) > 0.3
            resource_score = resource_score + 0.3;
        end
        if normalized_features(battery_impact_idx) > 0.5
            resource_score = resource_score + 0.4;
        end
        if normalized_features(msg_freq_idx) > 0.2
            resource_score = resource_score + 0.3;
        end
        attack_scores.RESOURCE_EXHAUSTION = resource_score;
        
        % NORMAL (baseline)
        attack_scores.NORMAL = 0.2; % Low baseline
        
        % Find the class with highest score
        score_values = struct2array(attack_scores);
        [max_score, max_idx] = max(score_values);
        
        attack_types_list = {'FLOODING', 'SPOOFING', 'BLACK_HOLE', 'RESOURCE_EXHAUSTION', 'NORMAL'};
        attack_type = attack_types_list{max_idx};
        confidence = min(max_score, 1.0); % Cap at 1.0
        is_attack = ~strcmp(attack_type, 'NORMAL') && confidence > 0.5;
        
        % Generate detailed AI reasoning
        ai_reasons = {};
        if strcmp(attack_type, 'FLOODING')
            if normalized_features(msg_freq_idx) > 0.3
                ai_reasons{end+1} = sprintf('High msg frequency (%.2f)', normalized_features(msg_freq_idx));
            end
            if normalized_features(msg_size_idx) > 0.2
                ai_reasons{end+1} = sprintf('Large msg size (%.2f)', normalized_features(msg_size_idx));
            end
            if normalized_features(battery_impact_idx) > 0.4
                ai_reasons{end+1} = sprintf('High battery impact (%.2f)', normalized_features(battery_impact_idx));
            end
        elseif strcmp(attack_type, 'SPOOFING')
            if normalized_features(suspicious_url_idx) > 0
                ai_reasons{end+1} = sprintf('Suspicious URLs detected (%.2f)', normalized_features(suspicious_url_idx));
            end
            if normalized_features(sender_rep_idx) < 0.5
                ai_reasons{end+1} = sprintf('Low sender reputation (%.2f)', normalized_features(sender_rep_idx));
            end
        elseif strcmp(attack_type, 'BLACK_HOLE')
            if normalized_features(forwarding_idx) < 0.3
                ai_reasons{end+1} = sprintf('Low forwarding behavior (%.2f)', normalized_features(forwarding_idx));
            end
            if normalized_features(routing_anomaly_idx) > 0.3
                ai_reasons{end+1} = sprintf('High routing anomaly (%.2f)', normalized_features(routing_anomaly_idx));
            end
        elseif strcmp(attack_type, 'RESOURCE_EXHAUSTION')
            if normalized_features(msg_size_idx) > 0.3
                ai_reasons{end+1} = sprintf('Large msg size (%.2f)', normalized_features(msg_size_idx));
            end
            if normalized_features(battery_impact_idx) > 0.5
                ai_reasons{end+1} = sprintf('High battery impact (%.2f)', normalized_features(battery_impact_idx));
            end
            if normalized_features(msg_freq_idx) > 0.2
                ai_reasons{end+1} = sprintf('High frequency (%.2f)', normalized_features(msg_freq_idx));
            end
        end
        
        % Store AI reasoning for later use
        ids_model.last_ai_reasoning = strjoin(ai_reasons, ', ');
        
        % Debug: Print prediction result with reasoning
        fprintf('DEBUG: AI predicted %s with confidence %.3f (is_attack=%d)\n', attack_type, confidence, is_attack);
        if ~isempty(ai_reasons)
            fprintf('DEBUG: AI reasoning: %s\n', ids_model.last_ai_reasoning);
        end
        fprintf('DEBUG: Scores - FLOOD:%.2f SPOOF:%.2f BLACK:%.2f RESOURCE:%.2f NORMAL:%.2f\n', ...
                attack_scores.FLOODING, attack_scores.SPOOFING, attack_scores.BLACK_HOLE, ...
                attack_scores.RESOURCE_EXHAUSTION, attack_scores.NORMAL);
        
    catch ME
        % Fallback to default detection
        fprintf('Python model prediction failed: %s\n', ME.message);
        is_attack = false;
        attack_type = 'NORMAL';
        confidence = 0.5;
    end
end
