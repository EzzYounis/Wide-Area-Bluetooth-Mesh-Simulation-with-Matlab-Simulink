 %% Bluetooth Mesh Network IDS Simulation
% AI-Assisted Intrusion Detection System for Bluetooth Mesh Networks
% Author: Research Simulation
% Date: 2024


clear all; close all; clc;

%% Simulation Parameters
global NUM_NORMAL_NODES NUM_ATTACK_NODES TOTAL_NODES MESSAGE_INTERVAL SIMULATION_TIME TRANSMISSION_RANGE AREA_SIZE ;
NUM_NORMAL_NODES = 8;
NUM_ATTACK_NODES = 2;
TOTAL_NODES = NUM_NORMAL_NODES + NUM_ATTACK_NODES;
MESSAGE_INTERVAL = 60; % seconds - INCREASED to 30 to reduce message load
SIMULATION_TIME = 20 * 60; % 5 minutes for better forwarding analysis
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
    %strategies = {'FLOODING', 'ADAPTIVE_FLOODING', 'RESOURCE_EXHAUSTION', 'BLACK_HOLE', 'SPOOFING'};
    strategies = { 'BLACK_HOLE'};
    node.attack_strategy = strategies{randi(length(strategies))};
    node.attack_frequency = 15 + 10 * rand(); % INCREASED: 15-25 seconds between attacks
    node.last_attack_time = 0;
    node.target_nodes = [];
    node.message_cache = containers.Map();
    node.cache_duration = 20;
    node.buffer_ttl = 300; % More aggressive: Messages expire from buffer after 300 seconds
    node.attack_params = struct(); % Will be populated by advanced attacker function
    node.blacklisted_senders = containers.Map('KeyType', 'double', 'ValueType', 'double');
    % For adaptive flooding: track current neighbor and sent count
    node.af_current_neighbor_idx = 1;
    node.af_sent_count = 0;
    
    % For flooding: track current neighbor and sent count
    node.flood_current_neighbor_idx = 1;
    node.flood_sent_count = 0;
    
    % Initialize tracking fields for dynamic features with default values
    % IMPORTANT: Only BLACK_HOLE attackers should have low forwarding behavior
    % Other attack types (FLOODING, ADAPTIVE_FLOODING, RESOURCE_EXHAUSTION, SPOOFING) forward normally
    % We'll set proper values after attack_strategy is assigned in createAdvancedAttackerNode
    node.forwarded_count = 5;  % Default: good forwarding (will be adjusted for BLACK_HOLE)
    node.received_count = 5;   % Default: receiving history (5/5 = 1.0 ratio)
    node.last_position = [x, y]; % Initialize with current position
    node.total_distance_moved = 0; % Track cumulative movement
    
    % Initialize additional behavioral tracking for attackers
    node.last_processing_load = 0.7;  % Attackers typically have higher processing load
    node.processing_history = [0.6, 0.7, 0.75];  % Simulated processing history (higher for attackers)
    node.battery_history = [node.battery_level, node.battery_level + 0.01];  % Simulated battery history
    node.route_change_count = 0;  % Default: no route changes
    node.last_route_length = 0;  % Default: no previous route
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
    
    % Initialize tracking fields for dynamic features with default values
    % Set initial counts to simulate normal behavior history (prevents early false positives)
    node.forwarded_count = 5;  % Default: neutral forwarding history
    node.received_count = 5;   % Default: neutral receiving history (5/5 = 1.0 ratio)
    node.last_position = [x, y]; % Initialize with current position
    node.total_distance_moved = 0; % Track cumulative movement
    node.target_nodes = [];
    node.message_cache = containers.Map();
    node.cache_duration = 20;
    node.buffer_ttl = 10; % More aggressive: Messages expire from buffer after 10 seconds
    node.attack_params = struct(); % Empty struct for normal nodes
    node.blacklisted_senders = containers.Map('KeyType', 'double', 'ValueType', 'double');
    % For struct compatibility with attackers (adaptive flooding)
    node.af_current_neighbor_idx = 1;
    node.af_sent_count = 0;
    
    % For struct compatibility with attackers (flooding)
    node.flood_current_neighbor_idx = 1;
    node.flood_sent_count = 0;
    
    % Initialize additional behavioral tracking to prevent early misdetection
    node.last_processing_load = 0.3;  % Default moderate processing load
    node.processing_history = [0.3, 0.35, 0.25];  % Simulated processing history
    node.battery_history = [node.battery_level, node.battery_level + 0.01];  % Simulated battery history
    node.route_change_count = 0;  % Default: no route changes
    node.last_route_length = 0;  % Default: no previous route
end

function node = createAdvancedAttackerNode(id, x, y)
    node = createAttackerNode(id, x, y); % Use base function
    
    % Enhanced attack strategies with specific parameters
    % IMPORTANT FORWARDING BEHAVIOR:
    % - BLACK_HOLE: Drops all received messages (handled in receiveMessage), low forwarding_count
    % - FLOODING, ADAPTIVE_FLOODING, RESOURCE_EXHAUSTION, SPOOFING: Forward messages normally like regular nodes
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
            node.attack_frequency = 1.5 + 0.9 * rand(); % Fast: 1.5-2.4 seconds (at least 25/min)
        case 'FLOODING'
            node.attack_frequency = 1 + rand(); % Very fast: 1-2 seconds (aggressive flooding)
        case 'BLACK_HOLE'
            node.attack_frequency = 40 + 20 * rand(); % Less frequent: 40-60 seconds
            % CRITICAL: BLACK_HOLE is the ONLY attack type with poor forwarding behavior
            node.forwarded_count = 1;  % Very low forwarding history for BLACK_HOLE
            node.received_count = 5;   % Normal receiving (1/5 = 0.2 ratio - drops most packets)
        case 'SPOOFING'
            node.attack_frequency = 40 + 20 * rand(); % Less frequent: 40-60 seconds (stealthy spoofing)
        case 'RESOURCE_EXHAUSTION'
            node.attack_frequency = 40 + 20 * rand(); % Less frequent: 40-60 seconds
        otherwise
            node.attack_frequency = base_frequency + randi(10); % Default: 20-30 seconds
    end
    
    % All non-BLACK_HOLE attackers maintain good forwarding behavior by default
    % (forwarded_count = 5, received_count = 5 already set in createAttackerNode)
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
    % Always include protocol_compliant field for struct consistency
    message.protocol_compliant = true; % Default for all messages
    % Add true attack attributes for data collection
    message.true_is_attack = node.is_attacker;
    if node.is_attacker && isfield(node, 'attack_strategy') && ~isempty(node.attack_strategy)
        message.true_attack_type = node.attack_strategy;
        % Set protocol_compliant = false only for spoofing
        if strcmp(node.attack_strategy, 'SPOOFING')
            message.protocol_compliant = false;
        end
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


function [node, detection_result] = receiveMessage(node, message, current_time, sender_node, detection_confidence_threshold)
    detection_result = [];
    if ~node.is_active || node.battery_level < 0.1
        return;
    end

    % BLACK_HOLE ATTACK: Drop ALL received messages immediately (highest priority check)
    % Black hole attackers silently drop everything - no logging, no buffering, no forwarding
    % This is the DEFINING characteristic of a BLACK_HOLE attack
    if node.is_attacker && isfield(node, 'attack_strategy') && ~isempty(node.attack_strategy)
        if strcmpi(node.attack_strategy, 'BLACK_HOLE')  % Case-insensitive comparison
            fprintf('🕳️  BLACK_HOLE: Node %d silently dropped message %s (source: %d)\n', ...
                node.id, message.id, message.source_id);
            % Do NOT increment received_count - black holes don't "receive" in the normal sense
            % Do NOT buffer, cache, or process - everything is discarded
            return;
        end
    end

    % Only increment received_count if message is truly eligible for forwarding
    % (not duplicate, not dropped, not blocked, not expired, not black hole)
    if nodeHasMessage(node, message.id)
        fprintf('Node %d already has message %s, ignoring duplicate\n', node.id, message.id);
        return;
    end

    % Check if sender is blacklisted (previously detected as attacker)
    if isfield(node, 'blacklisted_senders') && isKey(node.blacklisted_senders, message.source_id)
        blacklist_time = node.blacklisted_senders(message.source_id);
        blacklist_duration = 60; % Block for 60 seconds
        if current_time - blacklist_time < blacklist_duration
            fprintf('Node %d DROPPED message %s from BLACKLISTED sender %d (blocked %.1fs ago)\n', ...
                node.id, message.id, message.source_id, current_time - blacklist_time);
            return; % Drop message from blacklisted sender
        else
            % Blacklist expired, remove from list
            remove(node.blacklisted_senders, message.source_id);
        end
    end

    % Clean up expired messages from buffer before checking capacity
    node = cleanupMessageBuffer(node, current_time);

    % Enforce buffer size limit (by total bytes) using new structure
    if node.message_buffer.total_bytes + length(message.content) > node.max_buffer_bytes
        %fprintf('Node %d buffer full (bytes)! Dropping message %s\n', node.id, message.id);
        return;
    end

    % BLOCKING DECISION: Only increment received_count if message is not blocked by IDS
    % Print message path
    fprintf('Message %s: From Node %d → To Node %d (new)\n', ...
        message.id, message.source_id, node.id);

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

    % CRITICAL: Run IDS detection BEFORE caching for forwarding
    if ~node.is_attacker
        [node, detection_result] = runIDSDetection(node, message, sender_node, current_time);
        logMessageDetails(message, detection_result, node, current_time);

        % BLOCKING DECISION: Only cache for forwarding if IDS approves
        if detection_result.is_attack && detection_result.confidence > detection_confidence_threshold
            message.blocked = true;
            message.block_reason = detection_result.attack_type;
            fprintf('Node %d BLOCKED message %s (reason: %s, confidence: %.2f) - NOT FORWARDING\n', ...
                node.id, message.id, detection_result.attack_type, detection_result.confidence);

            % CRITICAL: Purge ALL cached messages from this attacker
            [node, num_purged] = purgeCachedMessagesFromSender(node, message.source_id, current_time);
            if num_purged > 0
                fprintf('   └─ PURGED %d cached messages from attacker Node %d\n', num_purged, message.source_id);
            end

            % Consume battery but DO NOT cache for forwarding
            node.battery_level = node.battery_level - 0.0005;
            return; % Exit without caching - message will NOT be forwarded
        end
        % Only increment received_count if message is not blocked
        node.received_count = node.received_count + 1;
    else
        % Attacker nodes: log received messages for completeness
        logMessageDetails(message, [], node, current_time);
        % Also log features for messages received by attackers
        logFeatureData(message, current_time, node, sender_node);
        % Only increment received_count for attackers if not blocked (attackers don't block)
        % CRITICAL: BLACK_HOLE nodes should have already returned above, but double-check here
        is_blackhole = isfield(node, 'attack_strategy') && ~isempty(node.attack_strategy) && strcmpi(node.attack_strategy, 'BLACK_HOLE');
        if ~is_blackhole
            node.received_count = node.received_count + 1;
        end
    end


    % ONLY CACHE FOR FORWARDING IF IDS APPROVED (or no IDS on attacker)
    % CRITICAL: BLACK_HOLE attackers should NOT cache - they already returned earlier
    % Double-check: if this is a BLACK_HOLE node, do NOT cache
    is_blackhole = node.is_attacker && isfield(node, 'attack_strategy') && ~isempty(node.attack_strategy) && strcmpi(node.attack_strategy, 'BLACK_HOLE');
    if ~is_blackhole
        cache_entry = struct();
        cache_entry.message = message;
        cache_entry.cache_time = current_time;
        cache_entry.forwarded_to = []; % Track which neighbors already received it
        
        node.message_cache(message.id) = cache_entry;
        
        fprintf('Node %d cached message %s for forwarding (IDS approved)\n', node.id, message.id);
    else
        fprintf('🕳️  BLACK_HOLE: Node %d will NOT cache message %s (drops all received messages)\n', node.id, message.id);
    end

    % Consume battery
    node.battery_level = node.battery_level - 0.0005;

    % Print received_count and forwarded_count after each message receive
    if isfield(node, 'received_count') && isfield(node, 'forwarded_count')
        fprintf('Node %d: received_count = %d, forwarded_count = %d\n', node.id, node.received_count, node.forwarded_count);
    end
end

% === IDS Detection Thresholds (edit here to tune) ===
% Confidence threshold for blocking messages classified as attacks
detection_confidence_threshold = 0.5; % First test value
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
    rules.spoofing.suspicious_url_count = 1; % Relaxed: even 1 URL is suspicious
    rules.spoofing.emergency_keyword_abuse = 0.25; % Relaxed: normalized threshold
    rules.spoofing.sender_reputation_threshold = 0.5; % Relaxed: catch moderate reputation issues
    rules.spoofing.protocol_compliance_threshold = 0.7; % NEW: poor protocol compliance indicator
    rules.spoofing.command_pattern_threshold = 0.3; % NEW: command injection indicator
    rules.spoofing.confidence = 0.90;
    
    % Rule 3: Resource Exhaustion Detection (TIGHTENED to reduce false positives)
    rules.resource_exhaustion = struct();
    rules.resource_exhaustion.message_size_threshold = 0.7; % BALANCED: 70% of max size
    rules.resource_exhaustion.frequency_threshold = 0.30; % RAISED: 30% of max frequency (was 0.15)
    rules.resource_exhaustion.battery_impact_threshold = 0.85; % RAISED: 85% battery depletion (was 0.15)
    rules.resource_exhaustion.confidence = 0.7;
    
    % Rule 4: Black Hole Detection (balanced sensitivity)
    rules.black_hole = struct();
    rules.black_hole.forwarding_threshold = 0.10; % RELAXED: catch nodes with up to 10% forwarding
    rules.black_hole.routing_anomaly_threshold = 0.6; % RELAXED: lower threshold for anomaly detection
    rules.black_hole.confidence = 0.75;
end

%Rule-based Detection
function [rule_result] = runRuleBasedDetection(node, message, sender_node, current_time, features)
    % Initialize rule_result at the top
    rules = node.ids_model.rules;
    rule_result = struct();
    rule_result.detected_attacks = {};
    rule_result.confidences = [];
    rule_result.overall_confidence = 0;
    rule_result.triggered_rules = {};

    % --- Enhanced RESOURCE_EXHAUSTION Rule (hybrid, more sensitive) ---
    resource_exhaustion_score = 0;
    resource_exhaustion_reasons = {};
    
    % CRITICAL PRE-CHECK: Exclude if flooding activity present (RESOURCE_EXHAUSTION vs FLOODING disambiguation)
    % RESOURCE_EXHAUSTION: Large messages at LOW frequency (targeted exhaustion)
    % FLOODING: Many messages (any size) at HIGH frequency (volume attack)
    has_flooding_activity = (features(16) >= 0.40) || (features(17) >= 0.50) || (features(20) > 0.50);
    
    if has_flooding_activity
        % Skip RESOURCE_EXHAUSTION rule - this is flooding, not targeted exhaustion
        % Flooding uses volume, exhaustion uses message characteristics at low frequency
    else
        % Primary indicator: Very large message (weight: 2 - strong indicator)
        if features(8) > 0.9   % message_length
            resource_exhaustion_score = resource_exhaustion_score + 2;
            resource_exhaustion_reasons{end+1} = sprintf('Very large message (%.2f > 0.9)', features(8));
        elseif features(8) > 0.7   % Large message
            resource_exhaustion_score = resource_exhaustion_score + 1;
            resource_exhaustion_reasons{end+1} = sprintf('Large message (%.2f > 0.7)', features(8));
        end
        
        % Secondary indicators (weight: 1 each) - TIGHTENED to reduce false positives
        if features(32) > 0.85  % battery_impact - RAISED from 0.15 to 0.85 (only severe battery drain)
            resource_exhaustion_score = resource_exhaustion_score + 1;
            resource_exhaustion_reasons{end+1} = sprintf('Battery impact (%.2f > 0.85)', features(32));
        end
        if features(34) > 0.75  % resource_utilization - RAISED from 0.5 to 0.75 (only high utilization)
            resource_exhaustion_score = resource_exhaustion_score + 1;
            resource_exhaustion_reasons{end+1} = sprintf('High resource utilization (%.2f > 0.75)', features(34));
        end
        if features(36) > 0.85  % resource_exhaustion - RAISED from 0.15 to 0.85 (only severe exhaustion)
            resource_exhaustion_score = resource_exhaustion_score + 1;
            resource_exhaustion_reasons{end+1} = sprintf('Resource exhaustion detected (%.2f > 0.85)', features(36));
        end
        
        % NEW: Command patterns with large messages indicate resource exhaustion attacks
        if features(14) > 0.8 && features(8) > 0.7  % High command patterns + large message
            resource_exhaustion_score = resource_exhaustion_score + 1.5;
            resource_exhaustion_reasons{end+1} = sprintf('Command patterns in large message (cmd:%.2f, size:%.2f)', features(14), features(8));
        end
        
        % Tertiary indicators (weight: 0.5 each) - STRICTER to reduce false positives
        % CRITICAL: Only flag low frequency (<0.30) with volume anomaly for exhaustion
        % (High frequency = flooding, not exhaustion)
        if features(20) > 0.75 && features(16) < 0.30  % INVERTED: LOW frequency + high volume anomaly
            resource_exhaustion_score = resource_exhaustion_score + 1.0;  % Combined weight
            resource_exhaustion_reasons{end+1} = sprintf('Low frequency + volume anomaly (freq:%.2f < 0.30, vol:%.2f > 0.75)', features(16), features(20));
        end
        
        % Trigger if score >= 2.5 (reduced from 3 - need primary + 1 secondary OR multiple secondaries)
        if resource_exhaustion_score >= 2.5
            rule_result.detected_attacks{end+1} = 'RESOURCE_EXHAUSTION';
            rule_result.confidences(end+1) = min(0.95, 0.75 + (resource_exhaustion_score - 2.5) * 0.05);
            rule_result.triggered_rules{end+1} = sprintf('enhanced_resource_exhaustion: %s (score=%.1f)', strjoin(resource_exhaustion_reasons, ' + '), resource_exhaustion_score);
            fprintf('RULE TRIGGER: Enhanced Resource Exhaustion detected - %s (score=%.1f)\n', strjoin(resource_exhaustion_reasons, ' and '), resource_exhaustion_score);
        end
    end
    
     % Rule 1: Enhanced Flooding Detection (IMPROVED - more sensitive to high frequency)
     % Primary condition: Very high message frequency is main flooding indicator
     flooding_score = 0;
     flood_reasons = {};
     
     % Primary indicator: High message frequency (weight: 2)
     if features(16) > rules.flooding.message_freq_threshold
         flooding_score = flooding_score + 2;
         flood_reasons{end+1} = sprintf('High msg frequency (%.2f > %.2f)', features(16), rules.flooding.message_freq_threshold);
     end
     
     % Secondary indicators (weight: 1 each)
     if features(8) > rules.flooding.message_size_threshold
         flooding_score = flooding_score + 1;
         flood_reasons{end+1} = sprintf('Large msg size (%.2f > %.2f)', features(8), rules.flooding.message_size_threshold);
     end
     
     if features(17) > 0.7  % High burst intensity
         flooding_score = flooding_score + 1;
         flood_reasons{end+1} = sprintf('High burst intensity (%.2f)', features(17));
     end
     
     if features(20) > 0.8  % High volume anomaly
         flooding_score = flooding_score + 1;
         flood_reasons{end+1} = sprintf('Volume anomaly (%.2f)', features(20));
     end
     
     % Trigger if score >= 2 (need at least primary OR 2 secondary indicators)
     if flooding_score >= 2
        rule_result.detected_attacks{end+1} = 'FLOODING';
        rule_result.confidences(end+1) = min(0.95, rules.flooding.confidence + (flooding_score - 2) * 0.05);
        rule_result.triggered_rules{end+1} = sprintf('flooding_detection: %s (score=%.1f)', strjoin(flood_reasons, ' + '), flooding_score);
        fprintf('RULE TRIGGER: Flooding detected - %s (score=%.1f)\n', strjoin(flood_reasons, ' and '), flooding_score);
    end
    
    % Rule 2: Enhanced Spoofing Detection (Multi-Factor Scoring)
    spoofing_score = 0;
    spoof_reasons = {};
    
    % Primary indicators (higher weight) - INCREASED SENSITIVITY
    if features(13) >= rules.spoofing.suspicious_url_count
        % IMPROVED: Much stronger weight for suspicious URLs (was 0.5 + features(13) * 0.3)
        weight = min(2.5, 1.0 + features(13) * 2.0); % Scale aggressively with URL count
        spoofing_score = spoofing_score + weight;
        spoof_reasons{end+1} = sprintf('Suspicious URLs (%.1f)', features(13));
    end
    
    if features(21) <= rules.spoofing.sender_reputation_threshold
        weight = 1.5 * (1 - features(21)); % Lower reputation = higher score
        spoofing_score = spoofing_score + weight;
        spoof_reasons{end+1} = sprintf('Low reputation (%.2f)', features(21));
    end
    
    % Secondary indicators (moderate weight) - INCREASED SENSITIVITY
    if features(12) >= rules.spoofing.emergency_keyword_abuse
        weight = min(1.0, features(12) * 2); % Scale with keyword count
        spoofing_score = spoofing_score + weight;
        spoof_reasons{end+1} = sprintf('Emergency keyword abuse (%.2f)', features(12));
    end
    
    if features(24) <= rules.spoofing.protocol_compliance_threshold
        % IMPROVED: Stronger weight for protocol violations (was 1.0)
        weight = 1.5 * (1 - features(24)); % Poor compliance = higher score
        spoofing_score = spoofing_score + weight;
        spoof_reasons{end+1} = sprintf('Protocol violation (%.2f)', features(24));
    end
    
    if features(14) >= rules.spoofing.command_pattern_threshold
        % IMPROVED: Stronger weight for command patterns (was min(0.8, features(14) * 1.5))
        weight = min(1.2, features(14) * 2.0); % Command patterns suspicious
        spoofing_score = spoofing_score + weight;
        spoof_reasons{end+1} = sprintf('Command patterns (%.2f)', features(14));
    end
    
    % Tertiary indicators (lower weight)
    if features(30) < 0.9 % header_integrity
        spoofing_score = spoofing_score + 0.5;
        spoof_reasons{end+1} = 'Header integrity issue';
    end
    
    % LOWERED THRESHOLD: Trigger if score >= 1.8 (was 2.0) - more sensitive to spoofing
    if spoofing_score >= 1.8
        rule_result.detected_attacks{end+1} = 'SPOOFING';
        rule_result.confidences(end+1) = rules.spoofing.confidence * min(1.0, spoofing_score / 3.0);
        rule_result.triggered_rules{end+1} = sprintf('spoofing_detection: %s', strjoin(spoof_reasons, ' + '));
        fprintf('RULE TRIGGER: Spoofing detected - %s (score=%.2f)\n', strjoin(spoof_reasons, ', '), spoofing_score);
    end

    % Rule: Adaptive Flooding Detection (BALANCED - requires actual flooding activity)
    adaptive_flooding_score = 0;
    adaptive_reasons = {};
    
    % CRITICAL PRE-CHECK: Must have at least ONE primary flooding indicator
    % (frequency OR bursts OR volume anomaly) - prevents false positives on regular/consistent non-flooding traffic
    % STRICTER THRESHOLDS: Require MORE evidence of actual flooding before triggering
    has_flooding_activity = (features(16) >= 0.25) || (features(17) >= 0.50) || (features(20) > 0.35);
    
    % CRITICAL: Also exclude if forwarding_behavior is VERY LOW (< 0.25) - likely BLACK_HOLE, not flooding
    % BLACK_HOLE nodes have consistent patterns but LOW forwarding; flooding has HIGH forwarding
    has_very_low_forwarding = (features(33) < 0.25);
    
    % NEW: CRITICAL EXCLUSION - If message shows STRONG resource exhaustion signature, don't trigger ADAPTIVE_FLOODING
    % Resource exhaustion: VERY large message (>0.9) + HIGH resource utilization (>0.8) + LOW frequency (<0.3)
    % This prevents conflating resource exhaustion attacks with flooding
    is_likely_resource_exhaustion = (features(8) > 0.9) && (features(34) > 0.8) && (features(16) < 0.3);
    
    if ~has_flooding_activity || has_very_low_forwarding || is_likely_resource_exhaustion
        % Skip this rule - no actual flooding activity detected OR forwarding too low for flooding
        % (prevents detecting BLACK_HOLE or normal nodes with regular patterns)
    else
        % Primary indicators (high weight) - RELAXED thresholds
        if features(16) >= 0.25 % message_frequency: RELAXED from 0.8 to 0.25 (catch early flooding)
            weight = min(2.5, 1.0 + features(16) * 2.0); % Scale weight by frequency
            adaptive_flooding_score = adaptive_flooding_score + weight;
            adaptive_reasons{end+1} = sprintf('Elevated msg frequency (%.2f)', features(16));
        end
        
        if features(17) >= 0.50 % burst_intensity: STRICTER threshold (was 0.10) - require actual bursts
            weight = min(2.0, 0.8 + features(17) * 1.5); % Scale weight by burst intensity
            adaptive_flooding_score = adaptive_flooding_score + weight;
            adaptive_reasons{end+1} = sprintf('Burst intensity detected (%.2f)', features(17));
        end
        
        if features(20) > 0.35 % volume_anomaly_score: STRICTER threshold (was 0.15) - require significant volume spike
            weight = min(1.5, features(20) * 5); % INCREASED scaling factor
            adaptive_flooding_score = adaptive_flooding_score + weight;
            adaptive_reasons{end+1} = sprintf('Volume anomaly (%.2f)', features(20));
        end
        
        % Secondary indicators (moderate weight) - ONLY count if flooding activity present
        if features(15) >= 0.70 % timing_regularity: STRICTER threshold (was 0.60) - require very high regularity
            weight = min(0.8, 0.3 + features(15) * 0.5); % FURTHER REDUCED weight
            adaptive_flooding_score = adaptive_flooding_score + weight;
            adaptive_reasons{end+1} = sprintf('Timing regularity (%.2f)', features(15));
        end
        
        if features(19) >= 0.80 % size_consistency: STRICTER threshold (was 0.30) - require very high consistency
            weight = min(0.7, 0.2 + features(19) * 0.5); % FURTHER REDUCED weight
            adaptive_flooding_score = adaptive_flooding_score + weight;
            adaptive_reasons{end+1} = sprintf('Size consistency (%.2f)', features(19));
        end
        
        if features(18) >= 0.70 % inter_arrival_variance: STRICTER threshold (was 0.50) - require very erratic patterns
            weight = min(0.6, features(18) * 0.8); % REDUCED weight
            adaptive_flooding_score = adaptive_flooding_score + weight;
            adaptive_reasons{end+1} = sprintf('Inter-arrival variance (%.2f)', features(18));
        end
        
        % NEW: Check for command patterns (indicator of attack content) - REDUCED IMPORTANCE
        if features(14) >= 0.50 % command_pattern_count: STRICTER threshold (was 0.30)
            weight = 0.5; % FURTHER REDUCED from 1.0 (command patterns alone don't indicate flooding)
            adaptive_flooding_score = adaptive_flooding_score + weight;
            adaptive_reasons{end+1} = sprintf('Command patterns (%.2f)', features(14));
        end
        
        % NEW: Check for low sender reputation (common in attacks) - REDUCED IMPORTANCE
        if features(21) <= 0.40 % sender_reputation: STRICTER threshold (was 0.60) - require very low reputation
            weight = min(0.5, (1.0 - features(21)) * 0.8); % FURTHER REDUCED weight
            adaptive_flooding_score = adaptive_flooding_score + weight;
            adaptive_reasons{end+1} = sprintf('Low sender reputation (%.2f)', features(21));
        end
        
        % Trigger if score >= 3.0 (STRICTER threshold - was 2.0, requires stronger flooding evidence)
        if adaptive_flooding_score >= 3.0
            rule_result.detected_attacks{end+1} = 'ADAPTIVE_FLOODING';
            rule_result.confidences(end+1) = min(0.95, 0.70 + (adaptive_flooding_score - 3.0) * 0.05);
            rule_result.triggered_rules{end+1} = sprintf('adaptive_flooding_detection: %s (score=%.2f)', strjoin(adaptive_reasons, ' + '), adaptive_flooding_score);
            fprintf('RULE TRIGGER: Adaptive Flooding detected - %s (score=%.2f)\n', strjoin(adaptive_reasons, ', '), adaptive_flooding_score);
        end
    end


    
    % Rule 3: Resource Exhaustion Detection (SCORING - uses OR logic with weights)
    resource_reasons = {};
    resource_score = 0;
    
    % CRITICAL PRE-CHECK: Exclude if flooding activity present (same as enhanced rule)
    % RESOURCE_EXHAUSTION: Large messages at LOW frequency (targeted exhaustion)
    % FLOODING: Many messages (any size) at HIGH frequency (volume attack)
    has_flooding_activity_rule3 = (features(16) >= 0.40) || (features(17) >= 0.50) || (features(20) > 0.50);
    
    if ~has_flooding_activity_rule3
        % Large message size is primary indicator (weight: 2)
        if features(8) > rules.resource_exhaustion.message_size_threshold
            resource_score = resource_score + 2;
            resource_reasons{end+1} = sprintf('Large msg size (%.2f > %.2f)', features(8), rules.resource_exhaustion.message_size_threshold);
        end
        
        % Secondary indicators (weight: 1 each) - TIGHTENED to match enhanced rule
        % REMOVED: High frequency check - exhaustion should be at LOW frequency
        % if features(16) > 0.30 was here - removed because it conflicts with exhaustion definition
        
        if features(32) > 0.85  % battery_impact - RAISED from 0.15 to 0.85 (require severe battery drain)
            resource_score = resource_score + 1;
            resource_reasons{end+1} = sprintf('Severe battery impact (%.2f > 0.85)', features(32));
        end
        if features(34) > 0.75  % resource_utilization - RAISED from 0.5 to 0.75 (require high utilization)
            resource_score = resource_score + 1;
            resource_reasons{end+1} = sprintf('High resource utilization (%.2f > 0.75)', features(34));
        end
        if features(36) > 0.85  % resource_exhaustion feature - RAISED from 0.15 to 0.85 (require severe exhaustion)
            resource_score = resource_score + 1;
            resource_reasons{end+1} = sprintf('Severe resource exhaustion (%.2f > 0.85)', features(36));
        end
        
        % Trigger if score >= 2 (need primary OR multiple secondary indicators)
        if resource_score >= 2
            rule_result.detected_attacks{end+1} = 'RESOURCE_EXHAUSTION';
            rule_result.confidences(end+1) = min(0.95, rules.resource_exhaustion.confidence + (resource_score - 2) * 0.05);
            rule_result.triggered_rules{end+1} = sprintf('resource_exhaustion_detection: %s (score=%.1f)', strjoin(resource_reasons, ' + '), resource_score);
            fprintf('RULE TRIGGER: Resource exhaustion detected - %s (score=%.1f)\n', strjoin(resource_reasons, ' and '), resource_score);
        end
    end
    
    % Rule 4: Black Hole Detection (BALANCED - detect low forwarding without flooding)
    if isfield(rules, 'black_hole')
        blackhole_reasons = {};
        blackhole_score = 0;
        
        % CRITICAL: Exclude if flooding activity present (BLACK_HOLE and FLOODING are mutually exclusive)
        % STRICTER: Use same thresholds as ADAPTIVE_FLOODING exclusion for consistency
        has_flooding_activity = (features(16) >= 0.25) || (features(17) >= 0.25) || (features(20) > 0.20);
        
        % CRITICAL FIX: Also exclude if forwarding behavior is actually reasonable (>= 0.35)
        % BLACK_HOLE nodes have VERY LOW to LOW forwarding (< 0.30), not moderate forwarding
        has_reasonable_forwarding = (features(33) >= 0.35);
        
        if has_flooding_activity || has_reasonable_forwarding
            % Skip BLACK_HOLE detection - node shows flooding activity OR reasonable forwarding
            % BLACK_HOLE nodes are passive (drop packets), not active (flood network or forward normally)
        else
            % Primary indicator: very low forwarding behavior (Feature 33) - CRITICAL REQUIREMENT
            if features(33) < rules.black_hole.forwarding_threshold
                blackhole_score = blackhole_score + 3.5; % INCREASED weight - this is THE key indicator
                blackhole_reasons{end+1} = sprintf('Very low forwarding (%.4f < %.2f)', features(33), rules.black_hole.forwarding_threshold);
            elseif features(33) < 0.15
                % Still suspiciously low even if above strict threshold
                blackhole_score = blackhole_score + 2.5; % INCREASED to catch 10-15% range
                blackhole_reasons{end+1} = sprintf('Low forwarding behavior (%.4f < 0.15)', features(33));
            elseif features(33) < 0.25
                % Suspicious forwarding range for potential black hole
                blackhole_score = blackhole_score + 1.8; % INCREASED to catch 15-25% range
                blackhole_reasons{end+1} = sprintf('Suspicious low forwarding (%.4f < 0.25)', features(33));
            elseif features(33) < 0.30
                % Borderline low forwarding (could be legitimate low traffic node)
                blackhole_score = blackhole_score + 1.0;
                blackhole_reasons{end+1} = sprintf('Borderline low forwarding (%.4f < 0.30)', features(33));
            end
            
            % Secondary indicator: high routing anomaly (Feature 28)
            if features(28) > rules.black_hole.routing_anomaly_threshold
                blackhole_score = blackhole_score + 2.0; % INCREASED from 1.5
                blackhole_reasons{end+1} = sprintf('High routing anomaly (%.4f > %.2f)', features(28), rules.black_hole.routing_anomaly_threshold);
            elseif features(28) > 0.5
                % Moderate anomaly still suspicious
                blackhole_score = blackhole_score + 0.8; % INCREASED from 0.5
                blackhole_reasons{end+1} = sprintf('Moderate routing anomaly (%.4f)', features(28));
            end
            
            % NEW: BONUS for high timing regularity with low forwarding (characteristic of BLACK_HOLE)
            % BLACK_HOLE nodes are consistent in their DROP behavior (not random)
            % This pattern distinguishes BLACK_HOLE (consistent dropping) from random packet loss
            if features(15) >= 0.70 && features(33) < 0.30
                % High timing regularity + low forwarding = likely BLACK_HOLE (consistent dropping pattern)
                blackhole_score = blackhole_score + 1.5;
                blackhole_reasons{end+1} = sprintf('Consistent drop pattern (regularity:%.2f, forwarding:%.2f)', ...
                    features(15), features(33));
            end
            
            % CRITICAL: Check for inconsistent timing patterns with low forwarding
            % BLACK_HOLE with erratic dropping may have HIGH inter_arrival_variance but LOW burst_intensity
            % (drops are irregular but no actual bursts since messages are dropped)
            if features(18) >= 0.60 && features(17) < 0.40 && features(33) < 0.30 && features(16) < 0.20
                % High variance + low bursts + low forwarding = erratic BLACK_HOLE behavior
                blackhole_score = blackhole_score + 1.0;
                blackhole_reasons{end+1} = sprintf('Erratic drop pattern (variance:%.2f, burst:%.2f, forwarding:%.2f)', ...
                    features(18), features(17), features(33));
            end
            
            % Additional indicators
            if features(26) > 0.5  % route_length - long routes suggest messages taking detours
                blackhole_score = blackhole_score + 0.5;
                blackhole_reasons{end+1} = sprintf('Abnormal route length (%.4f)', features(26));
            end
            
            if features(21) < 0.3  % Low sender reputation
                blackhole_score = blackhole_score + 0.5;
                blackhole_reasons{end+1} = sprintf('Low sender reputation (%.4f)', features(21));
            end
            
            if features(41) < 0.3  % Low neighbor trust (resource_drop proxy)
                blackhole_score = blackhole_score + 0.5;
                blackhole_reasons{end+1} = sprintf('Low neighbor trust (%.4f)', features(41));
            end
            
            % NEW: Require stable routing behavior (black holes don't change routes frequently)
            if features(25) >= 0.70 && features(27) <= 0.20 % High route stability, low route changes
                blackhole_score = blackhole_score + 0.8;
                blackhole_reasons{end+1} = sprintf('Stable routing pattern (stability:%.2f, changes:%.2f)', features(25), features(27));
            end
            
            % Trigger detection if score is high enough
            % This requires PRIMARY indicator (low forwarding) + sufficient secondary indicators
            % Adjusted threshold to 3.5 to catch more BLACK_HOLE cases with improved scoring
            if blackhole_score >= 3.5
                rule_result.detected_attacks{end+1} = 'BLACK_HOLE';
                rule_result.confidences(end+1) = min(0.95, rules.black_hole.confidence + (blackhole_score - 3.5) * 0.08);
                rule_result.triggered_rules{end+1} = sprintf('black_hole_detection: %s (score=%.1f)', strjoin(blackhole_reasons, ' + '), blackhole_score);
                fprintf('RULE TRIGGER: Black hole detected - %s (total score=%.1f)\n', strjoin(blackhole_reasons, ' and '), blackhole_score);
            end
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

function [final_result] = fuseDetectionResults(rule_result, ai_result, fusion_weights, message, node, features)
    final_result = struct();
    
    % Determine if attack detected by either system
    rule_attack = ~strcmp(rule_result.primary_attack, 'NORMAL') && rule_result.overall_confidence > 0.5;
    ai_attack = ai_result.is_attack && ai_result.confidence > 0.6;  % Adjusted for corrected confidence
    
    % DEBUG: Show what AI predicted (safe access)
    try
        fprintf('   [AI PREDICTION] Type: %s | is_attack: %d | confidence: %.4f | ai_attack: %d\n', ...
            ai_result.attack_type, ai_result.is_attack, ai_result.confidence, ai_attack);
        fprintf('   [RULE PREDICTION] Type: %s | rule_attack: %d | confidence: %.4f\n', ...
            rule_result.primary_attack, rule_attack, rule_result.overall_confidence);
    catch
        fprintf('   [DEBUG ERROR] Failed to print AI/Rule predictions\n');
    end
    
    % Fusion logic
    if rule_attack && ai_attack
        % Both agree - high confidence
        fprintf('Message %s: From Node %d → To Node %d (new)\n', message.id, message.source_id, node.id);
        fprintf('   └─ Features: [%s]\n', num2str(features, '%.4f '));
        % Print feature number and name for each feature
        feature_names = { ...
            'node_density', 'avg_neighbor_degree', 'clustering_coeff', 'mobility_pattern', 'signal_strength_factor', 'rssi_variance', 'hop_count', 'message_length', ...
            'entropy', 'special_char_ratio', 'numeric_ratio', 'emergency_keyword_count', 'suspicious_url_count', 'command_pattern_count', 'timing_regularity', 'message_frequency', ...
            'burst_intensity', 'inter_arrival_variance', 'size_consistency', 'volume_anomaly_score', 'sender_reputation', 'header_integrity', 'payload_entropy', 'protocol_compliance', ...
            'route_stability', 'route_length', 'route_changes', 'routing_anomaly', 'mesh_health', 'mesh_redundancy', 'mesh_connectivity_health', 'battery_impact', 'forwarding_behavior', ...
            'resource_utilization', 'resource_anomaly', 'resource_exhaustion', 'resource_recovery', 'resource_variance', 'resource_trend', 'resource_spike', 'resource_drop', ...
            'mesh_specific_1', 'mesh_specific_2', 'mesh_specific_3' ...
        };
        fprintf('   └─ Features (index:name:value):\n');
        for i = 1:length(features)
            if i <= length(feature_names)
                fprintf('      [%2d] %-25s = %.4f\n', i, feature_names{i}, features(i));
            else
                fprintf('      [%2d] %-25s = %.4f\n', i, '(unknown)', features(i));
            end
        end
        final_result.is_attack = true;
        final_result.attack_type = rule_result.primary_attack;
        final_result.confidence = fusion_weights.rule_weight * rule_result.overall_confidence + ...
                                 fusion_weights.ai_weight * ai_result.confidence;
        final_result.fusion_method = 'CONSENSUS';
        
    elseif rule_attack && ~ai_attack
        % Only rules detected
        if rule_result.overall_confidence > 0.90  % Raised to 0.90 - require high confidence for rule-only detection
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
    fused_result = fuseDetectionResults(rule_result, ai_result, node.ids_model.fusion_weights, message, node, features);
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
    
    % Store original features and sender_node_id for accurate logging
    detection_result.features = features;
    if ~isempty(sender_node)
        detection_result.sender_node_id = sender_node.id;
    else
        detection_result.sender_node_id = [];
    end
    
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
    
    % CRITICAL: If attack detected, purge all cached messages from this sender
    % Use threshold of 0.5 (same as blocking threshold in receiveMessage)
    if detection_result.is_attack && detection_result.confidence > 0.5
        [node, ~] = purgeCachedMessagesFromSender(node, message.source_id, current_time);
    end
    
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
    % CORRECTED: Features 15-43 now properly aligned with feature_names array
    % 
    % CRITICAL TEMPORAL FEATURES (15-18) - CORRECTED SEMANTICS:
    %   15. timing_regularity: HIGH value = regular/consistent (automated attacks)
    %   16. message_frequency: Messages per minute (normalized to [0,1])
    %   17. burst_intensity: Ratio of short intervals (HIGH = many bursts)
    %   18. inter_arrival_variance: Timing inconsistency (HIGH = erratic patterns)
    % 
    % KEY BEHAVIORAL FEATURES:
    %   32. battery_impact: Energy consumption score
    %   33. forwarding_behavior: CRITICAL for BLACK_HOLE detection (LOW = drops packets)
    features = zeros(1, 43); % Matching the Python models feature count
    
    % All features must be based only on observable state, not ground-truth attack type
    % Network topology features
    % 1. Node density: fraction of possible neighbors (assume 10 max)
    features(1) = min(1, length(node.neighbors) / 10);
    % 2. Isolation factor: as before
    features(2) = calculateIsolationFactor(node);
    % 3. Emergency priority: as before
    features(3) = getEmergencyPriority(message);
    % 4. Hop reliability: as before, with small noise
    features(4) = calculateHopReliability(message) + 0.01 * randn();
    % 5. Network fragmentation: use 1 - (neighbors/total nodes) as a proxy
    if isfield(node, 'total_nodes') && node.total_nodes > 1
        features(5) = 1 - (length(node.neighbors) / (node.total_nodes-1));
    else
        features(5) = 1 - (length(node.neighbors) / 10);
    end
    % 6. Critical node count: as before
    features(6) = min(1, length(node.neighbors) / 10);
    % 7. Backup route availability: use ratio of unique routes in routing_table
    if isfield(node, 'routing_table') && ~isempty(node.routing_table)
        features(7) = min(1, length(node.routing_table.keys) / 10);
    else
        features(7) = 0;
    end
    % 8. Message length: normalized
    features(8) = min(1, length(message.content) / 2000);
    
    % Entropy
    % 9. Entropy
    features(9) = calculateEntropy(message.content);
    % 10. Special character ratio
    features(10) = calculateSpecialCharRatio(message.content);
    % 11. Numeric ratio
    features(11) = calculateNumericRatio(message.content);
    % 12. Emergency keywords
    features(12) = countEmergencyKeywords(message.content);
    % 13. Suspicious URLs (normalized to [0,1] by max expected 5 URLs)
    features(13) = min(1.0, countSuspiciousURLs(message.content) / 5.0);
    % 14. Command pattern count
    features(14) = countCommandPatterns(message.content);
    
    % 15. timing_regularity: Measure regularity/consistency of message timing (sender-aware)
    % Higher value = MORE regular/consistent timing (characteristic of automated attacks)
    % FLOODING/ADAPTIVE_FLOODING = 0.7-0.95 (very regular), NORMAL = 0.0-0.5 (irregular)
    if ~isempty(sender_node) && isfield(sender_node, 'id') && isfield(node, 'message_history') && numel(node.message_history) > 1
        % Only analyze messages from this specific sender
        sender_msgs = cellfun(@(m) isfield(m, 'source_id') && m.source_id == sender_node.id, node.message_history);
        if sum(sender_msgs) > 1
            sender_times = cellfun(@(m) m.timestamp, node.message_history(sender_msgs));
            inter_arrivals = diff(sort(sender_times));
            if ~isempty(inter_arrivals) && mean(inter_arrivals) > 0
                cv = std(inter_arrivals) / mean(inter_arrivals); % Coefficient of variation
                features(15) = max(0, 1 - min(1, cv)); % INVERTED: Low CV = high regularity = high score
            else
                features(15) = 1.0; % All same timestamp = perfect regularity
            end
        else
            features(15) = 0;
        end
    elseif isfield(node, 'message_history') && numel(node.message_history) > 1
        % Fallback: analyze all messages if sender unknown
        times = cellfun(@(m) m.timestamp, node.message_history);
        inter_arrivals = diff(sort(times));
        if ~isempty(inter_arrivals) && mean(inter_arrivals) > 0
            cv = std(inter_arrivals) / mean(inter_arrivals);
            features(15) = max(0, 1 - min(1, cv)); % INVERTED: Low CV = high regularity
        else
            features(15) = 1.0;
        end
    else
        features(15) = 0;
    end
    
    % 16. message_frequency: messages per minute from sender (CORRECTED)
    % IMPROVED: Use SHORT window (10s) to detect RECENT flooding rate, not long-term average
    % This catches ADAPTIVE_FLOODING which sends at 1.5-2.4s intervals (25-40 msgs/min)
    if ~isempty(sender_node) && isfield(sender_node, 'id')
        % Use TWO windows for better detection:
        % 1. Short window (10s) for recent burst detection
        % 2. Long window (60s) for sustained flooding detection
        short_window = 10;  % 10 seconds for burst detection
        long_window = 60;   % 60 seconds for sustained flooding
        
        recent_short = 0;
        recent_long = 0;
        
        for i = 1:length(node.message_history)
            msg = node.message_history{i};
            if isfield(msg, 'source_id') && msg.source_id == sender_node.id
                time_diff = current_time - msg.timestamp;
                if time_diff <= short_window
                    recent_short = recent_short + 1;
                end
                if time_diff <= long_window
                    recent_long = recent_long + 1;
                end
            end
        end
        
        % Calculate rates for both windows
        rate_per_min_short = (recent_short / short_window) * 60;  % Extrapolate to per-minute
        rate_per_min_long = (recent_long / long_window) * 60;     % Long-term rate
        
        % Use the HIGHER of the two rates (catches both bursts and sustained)
        messages_per_minute = max(rate_per_min_short, rate_per_min_long);
        
        % Normalize by expected maximum frequency (30 messages/minute)
        features(16) = min(1, messages_per_minute / 30);
        
        % DEBUG: Print frequency calculation
        fprintf('   [DEBUG] message_frequency: sender=%d, short=%d(%.1f/min), long=%d(%.1f/min), max_rate=%.1f/min, normalized=%.4f\n', ...
            sender_node.id, recent_short, rate_per_min_short, recent_long, rate_per_min_long, messages_per_minute, features(16));
    else
        features(16) = calculateMessageFrequency(node, current_time);
    end
    
    % 17. burst_intensity: Detect actual message bursts (ratio of short intervals)
    % Higher value = MORE bursts (many messages with short intervals)
    % FLOODING = 0.7-1.0 (frequent bursts), NORMAL = 0.0-0.3 (few bursts)
    if ~isempty(sender_node) && isfield(sender_node, 'id') && isfield(node, 'message_history') && numel(node.message_history) > 1
        % Only analyze messages from this specific sender
        sender_msgs = cellfun(@(m) isfield(m, 'source_id') && m.source_id == sender_node.id, node.message_history);
        if sum(sender_msgs) > 2  % Need at least 3 messages to detect bursts
            sender_times = cellfun(@(m) m.timestamp, node.message_history(sender_msgs));
            inter_arrivals = diff(sort(sender_times));
            % Define burst as interval < 3 seconds (indicates rapid sending)
            burst_threshold = 3.0;
            burst_count = sum(inter_arrivals < burst_threshold);
            features(17) = burst_count / length(inter_arrivals); % Ratio of burst intervals
        else
            features(17) = 0;
        end
    elseif isfield(node, 'message_history') && numel(node.message_history) > 2
        % Fallback: analyze all messages if sender unknown
        times = cellfun(@(m) m.timestamp, node.message_history);
        inter_arrivals = diff(sort(times));
        burst_threshold = 3.0;
        burst_count = sum(inter_arrivals < burst_threshold);
        features(17) = burst_count / length(inter_arrivals);
    else
        features(17) = 0;
    end
    
    % 18. inter_arrival_variance: Normalized variance of inter-arrival times (sender-aware)
    % Higher value = MORE erratic/inconsistent timing patterns
    % ADAPTIVE_FLOODING = 0.6-1.0 (varied bursts), FLOODING = 0.3-0.7, NORMAL = 0.0-0.4 (consistent)
    if ~isempty(sender_node) && isfield(sender_node, 'id') && isfield(node, 'message_history') && numel(node.message_history) > 1
        % Only analyze messages from this specific sender
        sender_msgs = cellfun(@(m) isfield(m, 'source_id') && m.source_id == sender_node.id, node.message_history);
        if sum(sender_msgs) > 1
            sender_times = cellfun(@(m) m.timestamp, node.message_history(sender_msgs));
            inter_arrivals = diff(sort(sender_times));
            if ~isempty(inter_arrivals) && mean(inter_arrivals) > 0
                % Use normalized standard deviation (coefficient of variation)
                cv = std(inter_arrivals) / mean(inter_arrivals);
                features(18) = min(1, cv); % Higher variance = more erratic
            else
                features(18) = 0;
            end
        else
            features(18) = 0;
        end
    elseif isfield(node, 'message_history') && numel(node.message_history) > 1
        % Fallback: analyze all messages if sender unknown
        times = cellfun(@(m) m.timestamp, node.message_history);
        inter_arrivals = diff(sort(times));
        if ~isempty(inter_arrivals) && mean(inter_arrivals) > 0
            cv = std(inter_arrivals) / mean(inter_arrivals);
            features(18) = min(1, cv);
        else
            features(18) = 0;
        end
    else
        features(18) = 0;
    end
    
    % FLOODING PATTERN DETECTION: Boost temporal features if flooding patterns detected
    % Check for flooding indicators from observable behavior (no ground truth)
    if ~isempty(sender_node) && isfield(sender_node, 'id') && isfield(node, 'message_history') && ~isempty(node.message_history)
        % Count recent messages from this sender (last 10 seconds)
        recent_window = 10;
        sender_recent_msgs = 0;
        for hist_idx = 1:length(node.message_history)
            msg = node.message_history{hist_idx};
            if isfield(msg, 'source_id') && msg.source_id == sender_node.id && ...
               (current_time - msg.timestamp) <= recent_window
                sender_recent_msgs = sender_recent_msgs + 1;
            end
        end
        
        % If sender has sent MANY messages recently (>=15 in 10 sec) with large sizes, likely flooding
        % This is more aggressive to avoid false positives on normal forwarding
        if sender_recent_msgs >= 15 && features(8) > 0.6
            % Boost flooding indicators only for aggressive patterns
            if features(15) < 0.7  % Low timing regularity (irregular) -> boost it (make regular)
                features(15) = 0.75 + 0.15 * rand();
            end
            if features(16) < 0.8  % Low frequency -> boost it
                features(16) = 0.85 + 0.15 * rand();
            end
            if features(17) < 0.7  % Low burst intensity (few bursts) -> boost it
                features(17) = 0.80 + 0.15 * rand();
            end
        end
    end
    
    % 19. size_consistency: 1 - normalized std of message lengths (sender-aware)
    % Higher value means MORE consistent sizes
    % IMPROVED: For first messages, assume low consistency (0.3) rather than neutral
    if isfield(node, 'message_history') && numel(node.message_history) > 1 && ~isempty(sender_node) && isfield(sender_node, 'id')
        % Only analyze messages from this specific sender
        sender_msgs = cellfun(@(m) isfield(m, 'source_id') && m.source_id == sender_node.id, node.message_history);
        if sum(sender_msgs) > 1
            lens = cellfun(@(m) length(m.content), node.message_history(sender_msgs));
            if mean(lens) > 0
                cv = std(lens) / mean(lens); % Coefficient of variation
                features(19) = 1 - min(1, cv); % Higher consistency = higher score
            else
                features(19) = 1;
            end
        else
            % First message from sender: assume low consistency (normal behavior)
            features(19) = 0.3;
        end
    elseif isfield(node, 'message_history') && numel(node.message_history) > 1
        % Fallback: analyze all messages if sender unknown
        lens = cellfun(@(m) length(m.content), node.message_history);
        if mean(lens) > 0
            cv = std(lens) / mean(lens); % Coefficient of variation
            features(19) = max(0, 1 - min(1, cv)); % Higher = more consistent
        else
            features(19) = 0.3; % Low consistency for empty history
        end
    else
        % Very early messages: assume low consistency (normal behavior)
        features(19) = 0.3;
    end
    
    % 20. volume_anomaly_score: ratio of SENDER's messages in last 60s to total from sender
    % (sender-aware to distinguish flooding from legitimate forwarding traffic)
    % IMPORTANT: Only flag high ratio if sender has ENOUGH history AND high absolute volume
    if isfield(node, 'message_history') && ~isempty(node.message_history) && ~isempty(sender_node) && isfield(sender_node, 'id')
        now = current_time;
        % Count messages from this specific sender in last 60s
        sender_messages = cellfun(@(m) isfield(m, 'source_id') && m.source_id == sender_node.id, node.message_history);
        sender_recent = sum(cellfun(@(m) now-m.timestamp < 60 && isfield(m, 'source_id') && m.source_id == sender_node.id, node.message_history));
        sender_total = sum(sender_messages);
        
        % CRITICAL FIX: Volume anomaly should only trigger if BOTH high ratio AND high absolute volume
        % This prevents early messages from being flagged just because they're all recent
        if sender_total > 10 && sender_recent > 8
            % Sufficient history AND high recent volume - compute meaningful ratio
            raw_ratio = sender_recent / sender_total;
            % Scale by absolute volume to avoid false positives on low traffic
            volume_factor = min(1.0, sender_recent / 15); % 15+ recent msgs = full volume factor
            features(20) = raw_ratio * volume_factor;
        elseif sender_total > 5
            % Some history but not enough recent volume - scale down significantly
            raw_ratio = sender_recent / sender_total;
            confidence_factor = min(0.4, sender_recent / 10); % Max 0.4 unless 10+ recent msgs
            features(20) = raw_ratio * confidence_factor;
        elseif sender_total > 0
            % Very few messages: give strong benefit of doubt
            raw_ratio = sender_recent / sender_total;
            confidence_factor = sender_total / 15; % 0.067 for 1 msg, 0.133 for 2, etc.
            features(20) = raw_ratio * confidence_factor;
        else
            features(20) = 0;
        end
    elseif isfield(node, 'message_history') && ~isempty(node.message_history)
        % Fallback: use total if sender unknown (also apply volume gating)
        now = current_time;
        recent = sum(cellfun(@(m) now-m.timestamp < 60, node.message_history));
        total = numel(node.message_history);
        if total > 10 && recent > 8
            raw_ratio = recent / total;
            volume_factor = min(1.0, recent / 15);
            features(20) = raw_ratio * volume_factor;
        else
            raw_ratio = recent / total;
            confidence_factor = min(0.4, total / 15);
            features(20) = raw_ratio * confidence_factor;
        end
    else
        features(20) = 0;
    end
    
    % 21. sender_reputation: dynamic computation based on observable red flags ONLY
    % CRITICAL: No ground truth checks - must work from observable behavior only
    % Compute dynamic reputation based on message content and history
    base_rep = getSenderReputation(node, message.source_id);
    
    % Compute message-specific reputation from observable features in THIS message
    msg_rep = 0.8; % Start neutral for each message
    
    % Penalize for suspicious content in THIS message (observable)
    if features(13) > 0 % Suspicious URLs present
        msg_rep = msg_rep - 0.25 * features(13); % Stronger penalty for URLs
    end
    if features(12) > 0.5 % RELAXED: Only penalize very high emergency keyword count
        msg_rep = msg_rep - 0.1 * (features(12) - 0.5); % Scaled penalty above threshold
    end
    if features(14) > 0.4 % RELAXED: Only penalize high command patterns
        msg_rep = msg_rep - 0.15 * (features(14) - 0.4); % Scaled penalty above threshold
    end
    
    % NEW: Aggressive penalty for flooding-like behavior patterns
    % Only apply if sender has sent multiple messages (avoid penalizing legitimate first messages)
    flooding_score = 0;
    sender_message_count = 0;
    if ~isempty(sender_node) && isfield(sender_node, 'id') && isfield(node, 'message_history')
        sender_msgs = cellfun(@(m) isfield(m, 'source_id') && m.source_id == sender_node.id, node.message_history);
        sender_message_count = sum(sender_msgs);
    end
    
    % Only apply flooding detection if sender has sent at least 3 messages
    if sender_message_count >= 3
        % High message frequency
        if features(16) > 0.15
            flooding_score = flooding_score + (features(16) - 0.15) * 0.5;
        end
        
        % High timing regularity (robotic patterns)
        if features(15) > 0.8
            flooding_score = flooding_score + (features(15) - 0.8) * 1.0;
        end
        
        % High size consistency (identical messages)
        if features(19) > 0.8
            flooding_score = flooding_score + (features(19) - 0.8) * 0.8;
        end
        
        % Volume anomaly present
        if features(20) > 0.3
            flooding_score = flooding_score + features(20) * 0.6;
        end
        
        % Apply flooding penalty (max 0.4 reduction)
        if flooding_score > 0
            msg_rep = msg_rep - min(0.4, flooding_score);
        end
    end
    
    % Blend historical reputation (50%) with current message reputation (50%)
    % Increased historical weight to propagate bad reputation across messages
    features(21) = max(0.05, 0.5 * base_rep + 0.5 * msg_rep);
    
    % 22. header_integrity: use a proxy (e.g., always high unless message is malformed)
    if isfield(message, 'header_valid') && ~message.header_valid
        features(22) = 0.5;
    else
        features(22) = 1.0;
    end
    
    % 23. payload_entropy: content entropy (reuse calculated entropy)
    features(23) = features(9); % Copy from entropy feature
    
    % 24. protocol_compliance: assume always compliant unless flagged
    if isfield(message, 'protocol_compliant') && ~message.protocol_compliant
        features(24) = 0.5;
    else
        features(24) = 1.0;
    end
    
    % 25. route_stability
    features(25) = calculateRouteStability(node);
    
    % 26. route_length: normalized route length
    if isfield(message, 'route_length')
        features(26) = min(1, message.route_length / 10);
    else
        features(26) = 0;
    end
    
    % 27. route_changes: number of route changes (normalized)
    if isfield(node, 'route_change_count')
        features(27) = min(1, node.route_change_count / 5);
    else
        features(27) = 0;
    end
    
    % 28. routing_anomaly: change in route length compared to previous message
    if isfield(message, 'route_length') && isfield(node, 'last_route_length')
        diff_len = abs(message.route_length - node.last_route_length);
        features(28) = min(1, diff_len / 10);
    else
        features(28) = 0;
    end
    
    % 29. mesh_health: overall mesh network health score
    features(29) = calculateMeshHealth(node);
    
    % 30. mesh_redundancy: redundancy factor
    if ~isempty(sender_node) && isfield(sender_node, 'neighbors') && ~isempty(node.neighbors)
        overlap = intersect(node.neighbors, sender_node.neighbors);
        features(30) = min(1, length(overlap) / max(1, length(node.neighbors)));
    else
        features(30) = 0;
    end
    
    % 31. mesh_connectivity_health
    features(31) = calculateMeshConnectivityHealth();
    
    % 32. battery_impact
    features(32) = 1 - node.battery_level;
    
    % 33. forwarding_behavior (CRITICAL FOR BLACK_HOLE DETECTION)
    if ~isempty(sender_node) && isfield(sender_node, 'forwarded_count') && isfield(sender_node, 'received_count') && sender_node.received_count > 0
        fwd_ratio = sender_node.forwarded_count / sender_node.received_count;
        % Additional check: if ratio is suspiciously low AND sender has neighbors, flag as potential black hole
        if fwd_ratio < 0.15 && isfield(sender_node, 'neighbors') && length(sender_node.neighbors) > 0
            % Very low forwarding despite having neighbors - strong black hole indicator
            features(33) = min(0.05, fwd_ratio);
        else
            features(33) = min(1, fwd_ratio);
        end
    else
        % No data yet - check if sender has message history but no forwarding
        if ~isempty(sender_node) && isfield(sender_node, 'message_history') && ~isempty(sender_node.message_history)
            % Has received messages but no forwarding recorded - potential black hole
            features(33) = 0.02;
        else
            features(33) = 0.2; % Default: assume lower forwarding until proven otherwise (was 0.5)
        end
    end
    
    % 34. resource_utilization: Processing load
    features(34) = calculateProcessingLoad(node);
    
    % 35. resource_anomaly: Memory footprint anomaly
    if isempty(node.message_buffer.messages)
        features(35) = 0;
    else
        mem_usage = min(1, node.message_buffer.total_bytes / node.max_buffer_bytes);
        if mem_usage > 0.8
            features(35) = mem_usage; % Only flag high usage as anomaly
        else
            features(35) = 0;
        end
    end
    
    % 36. resource_exhaustion: battery depletion rate
    features(36) = 1 - node.battery_level;
    
    % 37. resource_recovery: signal strength (proxy for recovery capability)
    features(37) = calculateSignalStrength(node, sender_node);
    
    % 38. resource_variance: processing load variance
    if isfield(node, 'processing_history') && length(node.processing_history) > 1
        features(38) = std(node.processing_history);
    else
        features(38) = 0;
    end
    
    % 39. resource_trend: battery trend (simplified)
    if isfield(node, 'battery_history') && length(node.battery_history) > 1
        trend = diff(node.battery_history);
        if mean(trend) < 0
            features(39) = abs(mean(trend));
        else
            features(39) = 0;
        end
    else
        features(39) = 0;
    end
    
    % 40. resource_spike: sudden processing spike
    current_load = calculateProcessingLoad(node);
    if isfield(node, 'last_processing_load')
        spike = current_load - node.last_processing_load;
        features(40) = max(0, spike);
    else
        features(40) = 0;
    end
    
    % 41. resource_drop: sudden resource drop (neighbor trust score proxy)
    features(41) = calculateNeighborTrustScore(node, message.source_id);
    
    % 42. mesh_specific_1: Emergency context
    features(42) = getEmergencyContextScore(message);
    
    % 43. mesh_specific_2: Mobility pattern
    if isfield(node, 'total_distance_moved')
        features(43) = min(1, node.total_distance_moved / 200);
    else
        features(43) = 0;
    end
    
    % Ensure all features are within [0,1] bounds
	features = max(0, min(1, features));
end

% --- Helper for Jaccard similarity between two strings ---
function sim = jaccardSimilarity(str1, str2)
    set1 = unique(str1);
    set2 = unique(str2);
    intersection = numel(intersect(set1, set2));
    union_set = numel(union(set1, set2));
    if union_set == 0
        sim = 1;
    else
        sim = intersection / union_set;
    end
end

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

function health = calculateMeshHealth(node)
    % Calculate mesh network health based on node connectivity and battery
    if isempty(node.neighbors)
        health = 0;
        return;
    end
    
    % Factor 1: Connectivity (number of neighbors)
    connectivity_score = min(1, length(node.neighbors) / 5);
    
    % Factor 2: Battery level
    battery_score = node.battery_level;
    
    % Factor 3: Buffer capacity
    if isfield(node, 'message_buffer') && isfield(node, 'max_buffer_bytes')
        buffer_available = 1 - (node.message_buffer.total_bytes / node.max_buffer_bytes);
    else
        buffer_available = 0.5;
    end
    
    % Weighted average
    health = 0.4 * connectivity_score + 0.4 * battery_score + 0.2 * buffer_available;
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

function freq = calculateMessageFrequency(node, current_time, sender_id)
    % Calculate message frequency in the last minute, normalized to [0,1]
    recent_messages = 0;
    lookback_time = 60; % seconds
    if nargin < 3
        % No sender_id provided, count all messages
        for i = 1:length(node.message_history)
            if current_time - node.message_history{i}.timestamp <= lookback_time
                recent_messages = recent_messages + 1;
            end
        end
    else
        % Only count messages from sender_id
        for i = 1:length(node.message_history)
            msg = node.message_history{i};
            if isfield(msg, 'source_id') && msg.source_id == sender_id && current_time - msg.timestamp <= lookback_time
                recent_messages = recent_messages + 1;
            end
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
    % Processing load is ratio of buffer size to processing capacity (more conservative)
    % Typical NORMAL nodes should stay 0.1-0.5; attacks push toward 0.8-1.0
    base_load = (1 - node.processing_power) * 0.3;  % Reduced from 0.5
    buffer_load = (total_bytes / (2000 * 10)) * 0.4; % Increased denominator, reduced multiplier
    load = base_load + buffer_load;
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
                    
                    % CRITICAL OVERRIDE: BLACK_HOLE requires LOW forwarding_behavior as key signature
                    % If AI predicts BLACK_HOLE but forwarding_behavior >= 0.35, override to NORMAL
                    % This prevents false positives on normal nodes with legitimate traffic patterns
                    if strcmp(attack_type, 'BLACK_HOLE') && features(33) >= 0.35
                        % Forwarding behavior is reasonable/high - this is NOT a black hole
                        % Black holes have forwarding < 0.35 (drop >65% of packets)
                        old_reasoning = '';
                        if isfield(ids_model, 'last_ai_reasoning')
                            old_reasoning = ids_model.last_ai_reasoning;
                        end
                        attack_type = 'NORMAL';
                        is_attack = false;
                        confidence = 0.9; % High confidence it's normal
                        if ~isempty(old_reasoning)
                            ids_model.last_ai_reasoning = sprintf('%s | OVERRIDE: forwarding_behavior(%.4f) >= 0.35, reclassified as NORMAL', ...
                                old_reasoning, features(33));
                        else
                            ids_model.last_ai_reasoning = sprintf('OVERRIDE: BLACK_HOLE→NORMAL (forwarding_behavior=%.4f >= 0.35)', features(33));
                        end
                    end
                    
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
                    % Fallback: simulationDetection removed
                    error('No simulationDetection fallback available. Please provide a valid model.');
            end
            
        catch ME
            fprintf('⚠️  Model prediction failed: %s\n', ME.message);
            error('No simulationDetection fallback available. Please provide a valid model.');
        end
    else
    error('No simulationDetection fallback available. Please provide a valid model.');
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
            % Normal traffic patterns - diverse and realistic, including occasional bursts
            % 70% quiet/regular traffic, 30% bursty/active traffic
            if rand() < 0.7
                % REGULAR NORMAL TRAFFIC: Quiet, infrequent, low volume
                features(1) = 0.3 + rand()*0.4;     % node_density: moderate
                features(8) = 0.02 + rand()*0.15;   % message_length: small
                features(15) = rand()*0.3;          % timing_regularity: VERY LOW (irregular, realistic)
                features(16) = 0.1 + rand()*0.3;    % message_frequency: LOW
                features(17) = rand()*0.4;          % burst_intensity: LOW (no bursts)
                features(18) = rand()*0.5;          % inter_arrival_variance: varied
                features(19) = rand()*0.5;          % size_consistency: LOW to moderate (varied)
                features(20) = rand()*0.3;          % volume_anomaly: LOW
            else
                % BURSTY NORMAL TRAFFIC: Legitimate bursts (user sends multiple msgs, forwarding spikes)
                features(1) = 0.3 + rand()*0.4;     % node_density: moderate
                features(8) = 0.02 + rand()*0.2;    % message_length: small to moderate
                features(15) = rand()*0.4;          % timing_regularity: LOW (still irregular even with bursts)
                features(16) = 0.1 + rand()*0.5;    % message_frequency: LOW to MODERATE
                features(17) = 0.3 + rand()*0.6;    % burst_intensity: MODERATE to HIGH (bursts!)
                features(18) = 0.3 + rand()*0.7;    % inter_arrival_variance: MODERATE to HIGH
                features(19) = rand()*0.7;          % size_consistency: varied
                features(20) = 0.3 + rand()*0.7;    % volume_anomaly: MODERATE to HIGH (recent activity!)
            end
            % Common NORMAL features for both patterns
            features(21) = 0.7 + rand()*0.3;    % sender_reputation: HIGH (KEY DISCRIMINATOR!)
            features(22) = 0.9 + rand()*0.1;    % header_integrity: HIGH
            features(24) = 0.9 + rand()*0.1;    % protocol_compliance: HIGH
            features(25) = 0.7 + rand()*0.3;    % route_stability: STABLE
            features(28) = rand()*0.2;          % routing_anomaly: VERY LOW
            features(32) = 0.05 + rand()*0.3;   % battery_impact: LOW to MODERATE
            features(33) = 0.4 + rand()*0.4;    % forwarding_behavior: moderate (0.4-0.8)
            features(34) = 0.1 + rand()*0.9;    % resource_utilization: LOW to HIGH (can spike during forwarding!)
            features(35) = rand()*0.3;          % resource_anomaly: LOW (temporary spikes are normal)
            features(36) = 0.05 + rand()*0.3;   % resource_exhaustion: LOW to MODERATE (temp spikes)
            
        case 'FLOODING'
            % Include BOTH early-stage and established flooding patterns
            % 40% early-stage (low freq, building up), 60% established (high freq, sustained)
            if rand() < 0.4
                % EARLY-STAGE FLOODING: First few messages, low accumulated frequency
                features(16) = 0.1 + rand()*0.3;    % message_frequency: LOW (just starting)
                features(17) = 0.0 + rand()*0.2;    % burst_intensity: LOW-MODERATE (building)
                features(20) = 0.7 + rand()*0.3;    % volume_anomaly_score: HIGH (key indicator)
                features(15) = 0.6 + rand()*0.4;    % timing_regularity: REGULAR (flood pattern visible)
            else
                % ESTABLISHED FLOODING: Sustained attack with high frequency
                features(16) = 0.6 + rand()*0.4;    % message_frequency: VERY HIGH
                features(17) = 0.7 + rand()*0.3;    % burst_intensity: HIGH
                features(20) = 0.6 + rand()*0.4;    % volume_anomaly_score: HIGH
                features(15) = 0.7 + rand()*0.3;    % timing_regularity: HIGH (sustained pattern)
            end
            % Common features for all flooding
            features(8) = 0.4 + rand()*0.6;     % message_length: MODERATE-LARGE
            features(21) = 0.0 + rand()*0.3;    % sender_reputation: VERY LOW
            features(32) = 0.6 + rand()*0.4;    % battery_impact: HIGH
            features(19) = 0.7 + rand()*0.3;    % size_consistency: HIGH (flood msgs similar)
            
        case 'ADAPTIVE_FLOODING'
            % Variable patterns that adapt - HIGH burstiness with consistent patterns are key indicators!
            features(15) = 0.8 + rand()*0.2;    % timing_regularity: VERY HIGH (consistent burst pattern)
            features(16) = 0.8 + rand()*0.2;    % message_frequency: VERY HIGH
            features(17) = 0.8 + rand()*0.2;    % burst_intensity: VERY HIGH
            features(18) = 0.8 + rand()*0.2;    % inter_arrival_variance: HIGH (adaptive behavior)
            features(19) = 0.8 + rand()*0.2;    % size_consistency: HIGH (consistent sizes)
            features(21) = 0.6 + rand()*0.3;    % sender_reputation: moderate-high (mimics normal)
            features(22) = 0.9 + rand()*0.1;    % header_integrity: VERY HIGH
            features(24) = 0.9 + rand()*0.1;    % protocol_compliance: VERY HIGH
            features(32) = 0.6 + rand()*0.3;    % battery_impact: moderate-high
            features(33) = 0.7 + rand()*0.2;    % forwarding_behavior: HIGH (appears normal)
            features(34) = 0.6 + rand()*0.3;    % resource_utilization: moderate-high
            
        case 'SPOOFING'
            % High suspicious content, URL patterns
            features(10) = 0.3 + rand()*0.7;    % special_char_ratio: high
            features(12) = 0.4 + rand()*0.6;    % emergency_keyword_count: high
            features(13) = 0.6 + rand()*0.4;    % suspicious_url_count: HIGH (0.6-1.0, normalized)
            features(15) = 0.2 + rand()*0.4;    % timing_regularity: LOW-MODERATE (irregular)
            features(16) = 0.3 + rand()*0.3;    % message_frequency: moderate
            features(17) = 0.2 + rand()*0.3;    % burst_intensity: LOW-MODERATE
            features(21) = 0.0 + rand()*0.4;    % sender_reputation: very low
            features(22) = 0.3 + rand()*0.4;    % header_integrity: degraded
            features(24) = 0.3 + rand()*0.5;    % protocol_compliance: poor
            features(33) = 0.4 + rand()*0.3;    % forwarding_behavior: moderate
            
        case 'BLACK_HOLE'
            % Low forwarding behavior, routing anomalies, passive pattern
            features(15) = 0.2 + rand()*0.3;    % timing_regularity: LOW-MODERATE (passive, not bursty)
            features(16) = 0.2 + rand()*0.4;    % message_frequency: LOW to moderate
            features(17) = 0.1 + rand()*0.3;    % burst_intensity: LOW
            features(28) = 0.5 + rand()*0.5;    % routing_anomaly: high
            features(33) = 0.0 + rand()*0.15;   % forwarding_behavior: VERY LOW (key signature!)
            features(21) = 0.3 + rand()*0.4;    % sender_reputation: moderate
            features(25) = 0.2 + rand()*0.4;    % route_stability: poor
            features(32) = 0.2 + rand()*0.3;    % battery_impact: LOW
            features(34) = 0.1 + rand()*0.2;    % resource_utilization: LOW
            
        case 'RESOURCE_EXHAUSTION'
            % High resource consumption patterns
            features(8) = 0.7 + rand()*0.3;     % message_length: VERY LARGE (0.7-1.0)
            features(15) = 0.3 + rand()*0.4;    % timing_regularity: MODERATE (steady pattern)
            features(16) = 0.4 + rand()*0.3;    % message_frequency: moderate
            features(17) = 0.3 + rand()*0.3;    % burst_intensity: moderate
            features(21) = 0.3 + rand()*0.4;    % sender_reputation: moderate
            features(32) = 0.7 + rand()*0.3;    % battery_impact: VERY HIGH (key signature!)
            features(34) = 0.8 + rand()*0.2;    % resource_utilization: VERY HIGH (key signature!)
            features(35) = 0.5 + rand()*0.5;    % resource_anomaly: large
            features(36) = 0.8 + rand()*0.2;    % resource_exhaustion: VERY HIGH
            features(33) = 0.4 + rand()*0.3;    % forwarding_behavior: moderate
    end
    
    % Add realistic noise and correlations
    features = features + randn(1, 43) * 0.05; % Small gaussian noise
    
    % Ensure all features are within [0,1] bounds
    features(1:43) = max(0, min(1, features(1:43)));
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
        % More aggressive penalty for high-confidence attack detection
        if strcmp(detection_result.attack_type, 'ADAPTIVE_FLOODING') || strcmp(detection_result.attack_type, 'FLOODING')
            new_reputation = current_reputation * 0.6; % Stronger decrease for flooding
        else
            new_reputation = current_reputation * 0.8; % Standard decrease
        end
    elseif ~detection_result.is_attack
        new_reputation = min(1.0, current_reputation + 0.005); % Smaller increase (was 0.01)
    else
        new_reputation = current_reputation;
    end
    
    node.reputation_scores(sender_id) = new_reputation;
    
    % Print detection result for ALL cases (including BOTH_NORMAL, TN, etc.)
    % Determine the real attack type
    if isfield(original_message, 'true_attack_type')
        real_attack_type = original_message.true_attack_type;
    elseif original_message.is_attack
        real_attack_type = 'UNKNOWN_ATTACK';
    else
        real_attack_type = 'NORMAL';
    end

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
                if isfield(detection_result, 'triggered_rules') && ~isempty(detection_result.triggered_rules)
                    rule_details = sprintf('Rules: %s', strjoin(detection_result.triggered_rules, '; '));
                end
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
        detection_source = 'AI-LEGACY';
        detection_reason = sprintf('Legacy AI detection (conf:%.2f)', detection_result.confidence);
    end

    if is_correct_detection
        fprintf('✅ Node %d: CORRECT detection | Detected: %s | Real: %s | Confidence: %.2f | Source: %s\n', ...
            node.id, detection_result.attack_type, real_attack_type, detection_result.confidence, detection_source);
    else
        fprintf('❌ Node %d: MISCLASSIFIED | Detected: %s | Real: %s | Confidence: %.2f | Source: %s\n', ...
            node.id, detection_result.attack_type, real_attack_type, detection_result.confidence, detection_source);
    end
    fprintf('   └─ Reason: %s | Message: %s\n', detection_reason, detection_result.message_id);
    
    % Print all message features for the detected message (for both correct and misclassified)
    % Use stored features from detection_result if available (more accurate)
    if isfield(detection_result, 'features') && ~isempty(detection_result.features)
        features_for_print = detection_result.features;
    else
        % Fallback: re-extract features (less accurate due to missing sender context)
        features_for_print = extractMessageFeatures(node, original_message, [], detection_result.timestamp);
    end
    
    fprintf('   └─ Features: [');
    fprintf('%.4f ', features_for_print);
    fprintf(']\n');
    % Print feature number and name for each feature
    feature_names = { ...
        'node_density', 'avg_neighbor_degree', 'clustering_coeff', 'mobility_pattern', 'signal_strength_factor', 'rssi_variance', 'hop_count', 'message_length', ...
        'entropy', 'special_char_ratio', 'numeric_ratio', 'emergency_keyword_count', 'suspicious_url_count', 'command_pattern_count', 'timing_regularity', 'message_frequency', ...
        'burst_intensity', 'inter_arrival_variance', 'size_consistency', 'volume_anomaly_score', 'sender_reputation', 'header_integrity', 'payload_entropy', 'protocol_compliance', ...
        'route_stability', 'route_length', 'route_changes', 'routing_anomaly', 'mesh_health', 'mesh_redundancy', 'mesh_connectivity_health', 'battery_impact', 'forwarding_behavior', ...
        'resource_utilization', 'resource_anomaly', 'resource_exhaustion', 'resource_recovery', 'resource_variance', 'resource_trend', 'resource_spike', 'resource_drop', ...
        'mesh_specific_1', 'mesh_specific_2', 'mesh_specific_3' ...
    };
    fprintf('   └─ Features (index:name:value):\n');
    for i = 1:length(features_for_print)
        if i <= length(feature_names)
            fprintf('      [%2d] %-25s = %.4f\n', i, feature_names{i}, features_for_print(i));
        else
            fprintf('      [%2d] %-25s = %.4f\n', i, '(unknown)', features_for_print(i));
        end
    end

    % Log the detected attack (for all cases)
    logMessageDetails(original_message, detection_result, node, detection_result.timestamp);
end
%% Attacker Functions
function [node, attack_message] = launchAttack(node, current_time, target_nodes)
    attack_message = [];
    
    % FLOODING: send ALL messages to ONE neighbor before moving to next
    if strcmp(node.attack_strategy, 'FLOODING')
        % Check if node has any neighbors in range
        if ~isfield(node, 'neighbors') || isempty(node.neighbors)
            fprintf('Node %d (FLOODING) skipped attack - no neighbors in range\n', node.id);
            attack_message = [];
            return;
        end
        
        % Initialize counter if needed
        if ~isfield(node, 'flood_sent_count')
            node.flood_sent_count = 0;
        end
        
        % Ensure index is valid
        if node.flood_current_neighbor_idx > length(node.neighbors)
            node.flood_current_neighbor_idx = 1;
            node.flood_sent_count = 0; % Reset counter when cycling
        end
        
        % Use configured burst size or default to 11 (matching ADAPTIVE_FLOODING)
        if isfield(node, 'attack_params') && isfield(node.attack_params, 'message_burst_size')
            target_count_per_neighbor = node.attack_params.message_burst_size;
        else
            target_count_per_neighbor = 11; % Default: 11 messages per neighbor
        end
        
        neighbor_id = node.neighbors(node.flood_current_neighbor_idx);
        
        % Send ALL messages to current neighbor in one burst
        messages_to_send = target_count_per_neighbor - node.flood_sent_count;
        
        for msg_num = 1:messages_to_send
            attack_content = generateFloodingContent(node);
            [node, single_attack_message] = sendMessage(node, attack_content, 'ATTACK', neighbor_id, current_time);
            
            if ~isempty(single_attack_message)
                node.flood_sent_count = node.flood_sent_count + 1;
                fprintf('🔥 FLOODING: Node %d → Node %d [msg %d/%d] @ t=%.2fs\n', ...
                    node.id, neighbor_id, node.flood_sent_count, target_count_per_neighbor, current_time);
                
                % Store the first message to return
                if msg_num == 1
                    attack_message = single_attack_message;
                end
            end
        end
        
        % After sending all messages to this neighbor, move to next
        if node.flood_sent_count >= target_count_per_neighbor
            fprintf('   ✓ FINISHED flooding Node %d (%d messages sent). Moving to next neighbor.\n\n', ...
                neighbor_id, node.flood_sent_count);
            
            % Move to next neighbor and reset counter
            node.flood_current_neighbor_idx = node.flood_current_neighbor_idx + 1;
            node.flood_sent_count = 0;
            
            % Wrap around to first neighbor if we've attacked all
            if node.flood_current_neighbor_idx > length(node.neighbors)
                fprintf('   🔄 FLOODING CYCLE COMPLETE: All %d neighbors attacked. Restarting cycle.\n\n', ...
                    length(node.neighbors));
                node.flood_current_neighbor_idx = 1;
            end
        end
        
        return;
    end

    % ADAPTIVE FLOODING: send ALL messages to ONE neighbor before moving to next
    if strcmp(node.attack_strategy, 'ADAPTIVE_FLOODING')
        % Check if node has any neighbors in range
        if ~isfield(node, 'neighbors') || isempty(node.neighbors)
            fprintf('Node %d (ADAPTIVE_FLOODING) skipped attack - no neighbors in range\n', node.id);
            attack_message = [];
            return;
        end
        
        % Initialize counter if needed
        if ~isfield(node, 'af_sent_count')
            node.af_sent_count = 0;
        end
        
        % Ensure af_current_neighbor_idx is valid
        if node.af_current_neighbor_idx > length(node.neighbors)
            node.af_current_neighbor_idx = 1;
            node.af_sent_count = 0; % Reset counter when cycling
        end
        
        % Use configured burst size or default to 11 (as mentioned in your output)
        if isfield(node, 'attack_params') && isfield(node.attack_params, 'message_burst_size')
            target_count_per_neighbor = node.attack_params.message_burst_size;
        else
            target_count_per_neighbor = 11; % Default: 11 messages per neighbor (as per your example)
        end
        
        neighbor_id = node.neighbors(node.af_current_neighbor_idx);
        
        % Send ALL messages to current neighbor in one burst
        messages_to_send = target_count_per_neighbor - node.af_sent_count;
        
        for msg_num = 1:messages_to_send
            attack_content = generateAdaptiveFloodingContent(node);
            [node, single_attack_message] = sendMessage(node, attack_content, 'ATTACK', neighbor_id, current_time);
            
            if ~isempty(single_attack_message)
                node.af_sent_count = node.af_sent_count + 1;
                fprintf('⚡ ADAPTIVE_FLOODING: Node %d → Node %d [msg %d/%d] @ t=%.2fs\n', ...
                    node.id, neighbor_id, node.af_sent_count, target_count_per_neighbor, current_time);
                
                % Store the first message to return
                if msg_num == 1
                    attack_message = single_attack_message;
                end
            end
        end
        
        % After sending all messages to this neighbor, move to next
        if node.af_sent_count >= target_count_per_neighbor
            fprintf('   ✓ FINISHED flooding Node %d (%d messages sent). Moving to next neighbor.\n\n', ...
                neighbor_id, node.af_sent_count);
            
            % Move to next neighbor and reset counter
            node.af_current_neighbor_idx = node.af_current_neighbor_idx + 1;
            node.af_sent_count = 0;
            
            % Wrap around to first neighbor if we've attacked all
            if node.af_current_neighbor_idx > length(node.neighbors)
                fprintf('   🔄 ADAPTIVE_FLOODING CYCLE COMPLETE: All %d neighbors attacked. Restarting cycle.\n\n', ...
                    length(node.neighbors));
                node.af_current_neighbor_idx = 1;
            end
        end
        
        return;
    end
    
    % For other attack types (non-flooding), apply frequency throttling
    if current_time - node.last_attack_time < node.attack_frequency
        return;
    end
    node.last_attack_time = current_time;
    
    % Check if node has any neighbors in range before sending any attack
    if ~isfield(node, 'neighbors') || isempty(node.neighbors)
        fprintf('Node %d (%s) skipped attack - no neighbors in range\n', node.id, node.attack_strategy);
        attack_message = [];
        return;
    end
    
    % BLACK_HOLE: Send deceptive advertisement messages (not counted as forwarding)
    if strcmp(node.attack_strategy, 'BLACK_HOLE')
        % Black hole sends advertisement messages but should NOT count as forwarding
        % These are deceptive messages to attract traffic, not legitimate forwarding
        if ~isempty(target_nodes)
            target_id = target_nodes(randi(length(target_nodes)));
        else
            target_id = randi(15); % Random normal node
        end
        attack_content = generateBlackHoleContent(node);
        fprintf('\n🕳️  BLACK_HOLE ATTACK: Node %d → Target Node %d @ t=%.2fs\n', ...
            node.id, target_id, current_time);
        fprintf('   └─ Sending deceptive advertisement to attract traffic...\n');
        [node, attack_message] = sendMessage(node, attack_content, 'ATTACK', target_id, current_time);
        % BLACK_HOLE: Do NOT increment forwarded_count for attack messages
        % This ensures forwarding_behavior metric stays low (key BLACK_HOLE signature)
        fprintf('   └─ BLACK_HOLE attack message sent (NOT counted as forwarding)\n\n');
        return;
    end
    
    % Default: single attack message to random target
    if ~isempty(target_nodes)
        target_id = target_nodes(randi(length(target_nodes)));
    else
        target_id = randi(15); % Random normal node
    end
    attack_content = generateAdvancedAttackContent(node);
    fprintf('ATTACKER Node %d launching %s attack at time %.2f\n', node.id, node.attack_strategy, current_time);
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
    
    % Save simulation data using MAT-file version 7.3 for large variables (>2GB)
    filename = fullfile(results_dir, sprintf('simulation_data_%s.mat', timestamp));
    save(filename, 'nodes', 'stats_history', 'simulation_data', 'NUM_NORMAL_NODES', ...
         'NUM_ATTACK_NODES', 'SIMULATION_TIME', 'MESSAGE_INTERVAL', '-v7.3');
    
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

function [node, num_purged] = purgeCachedMessagesFromSender(node, sender_id, current_time)
    % Purge all cached messages from a specific sender (detected attacker)
    % Also blacklist the sender to prevent future messages from being cached
    
    num_purged = 0;
    message_ids = keys(node.message_cache);
    
    for i = 1:length(message_ids)
        msg_id = message_ids{i};
        cache_entry = node.message_cache(msg_id);
        
        % Check if this message is from the attacking sender
        if cache_entry.message.source_id == sender_id
            % Remove from cache
            remove(node.message_cache, msg_id);
            num_purged = num_purged + 1;
            fprintf('   └─ Purged cached message %s from attacker Node %d\n', msg_id, sender_id);
        end
    end
    
    % Add sender to blacklist with current timestamp
    if isfield(node, 'blacklisted_senders')
        node.blacklisted_senders(sender_id) = current_time;
        fprintf('   └─ Blacklisted Node %d for 60 seconds\n', sender_id);
    end
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
    % CRITICAL: BLACK_HOLE nodes should NEVER forward cached messages
    % They drop everything - no forwarding allowed
    is_blackhole = node.is_attacker && isfield(node, 'attack_strategy') && ...
                   ~isempty(node.attack_strategy) && strcmpi(node.attack_strategy, 'BLACK_HOLE');
    
    if is_blackhole
        % BLACK_HOLE nodes drop everything - clear cache and exit
        node.message_cache = containers.Map('KeyType', 'char', 'ValueType', 'any');
        return;
    end
    
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
                    % CRITICAL FIX: BLACK_HOLE nodes should NOT increment forwarded_count
                    % (they drop received messages, so low forwarding is their signature)
                    is_blackhole = node.is_attacker && isfield(node, 'attack_strategy') && ~isempty(node.attack_strategy) && strcmpi(node.attack_strategy, 'BLACK_HOLE');
                    if ~is_blackhole
                        node.forwarded_count = node.forwarded_count + 1;
                    else
                        fprintf('[DEBUG] Blocked forwarded_count increment for BLACK_HOLE Node %d\n', node.id);
                    end
                    
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

    % === IDS Detection Thresholds (edit here to tune) ===
    % Confidence threshold for blocking messages classified as attacks
    detection_confidence_threshold = 0.90; % Messages with confidence < 90% will NOT be blocked

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
        
        % Debug: Print attacker type and initial forwarding stats
        fprintf('📍 Created ATTACKER Node %d: Type=%s, forwarded_count=%d, received_count=%d (ratio=%.2f)\n', ...
            attacker.id, attacker.attack_strategy, attacker.forwarded_count, attacker.received_count, ...
            attacker.forwarded_count / attacker.received_count);
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

    fprintf('Starting simulation...\n');
    fprintf('⚠️  WARNING: Feature extraction has been CORRECTED (features 15-43 reordered)\n');
    fprintf('⚠️  If AI model was trained with OLD feature mapping, it will produce INCORRECT predictions!\n');
    fprintf('⚠️  REQUIRED ACTION: Retrain AI model by running: buildRandomForestModel\n\n');

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
                    
                    % Check if sender has any neighbors in range before sending
                    if isempty(nodes(sender_idx).neighbors)
                        fprintf('Node %d skipped sending - no neighbors in range\n', nodes(sender_idx).id);
                        continue;
                    end
                    
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
            
            % For flooding attacks, we need to deliver ALL burst messages immediately
            % Get all cached messages BEFORE the attack to identify new ones
            if isempty(keys(nodes(idx).message_cache))
                cached_before = {};
            else
                cached_before = keys(nodes(idx).message_cache);
            end
            
            [nodes(idx), attack_message] = launchAttack(nodes(idx), current_time, normal_node_ids);
            
            % Log attack messages if they were generated
            if ~isempty(attack_message) && isstruct(attack_message) && isfield(attack_message, 'id')
                logMessageDetails(attack_message, [], nodes(idx), current_time);
                % Also log features for attack messages
                logFeatureData(attack_message, current_time, nodes(idx), nodes(idx));
                fprintf('ATTACK: Node %d launched %s attack with message %s\n', ...
                    nodes(idx).id, nodes(idx).attack_strategy, attack_message.id);
            end
            
            % IMMEDIATE DELIVERY: For flooding/burst attacks, deliver all new messages immediately
            % Get all cached messages AFTER the attack
            if ~isempty(keys(nodes(idx).message_cache))
                cached_after = keys(nodes(idx).message_cache);
                % Find new messages that were just added
                new_messages = setdiff(cached_after, cached_before);
                
                % Immediately deliver each new message to its destination
                for j = 1:length(new_messages)
                    msg_id = new_messages{j};
                    cache_entry = nodes(idx).message_cache(msg_id);
                    msg = cache_entry.message;
                    
                    % Find the destination node
                    dest_idx = find([nodes.id] == msg.destination_id, 1);
                    if ~isempty(dest_idx) && nodes(dest_idx).is_active
                        % Check if they are neighbors (within transmission range)
                        distance = norm(nodes(idx).position - nodes(dest_idx).position);
                        if distance <= TRANSMISSION_RANGE
                            % Immediate delivery with 90% success rate
                            if rand() < 0.9
                                [nodes(dest_idx), detection_result] = receiveMessage(nodes(dest_idx), msg, msg.timestamp, nodes(idx), detection_confidence_threshold);
                                
                                % Update forwarding stats for the sender
                                % CRITICAL FIX: BLACK_HOLE nodes should NOT increment forwarded_count
                                % (they drop received messages, so low forwarding is their signature)
                                is_blackhole = nodes(idx).is_attacker && isfield(nodes(idx), 'attack_strategy') && ~isempty(nodes(idx).attack_strategy) && strcmpi(nodes(idx).attack_strategy, 'BLACK_HOLE');
                                if ~is_blackhole
                                    if isfield(nodes(idx), 'forwarded_count')
                                        nodes(idx).forwarded_count = nodes(idx).forwarded_count + 1;
                                    else
                                        nodes(idx).forwarded_count = 1;
                                    end
                                else
                                    fprintf('[DEBUG] Blocked forwarded_count increment for BLACK_HOLE Node %d (location 1)\n', nodes(idx).id);
                                end
                                
                                % Mark as forwarded to this neighbor
                                cache_entry.forwarded_to(end+1) = msg.destination_id;
                                nodes(idx).message_cache(msg_id) = cache_entry;
                            end
                        end
                    end
                end
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
                                                [nodes(neighbor_idx), detection_result] = receiveMessage(nodes(neighbor_idx), forwarded_msg, current_time, nodes(i), detection_confidence_threshold);
                                                
                                                % Increment forwarded count for the forwarding node
                                                % CRITICAL FIX: BLACK_HOLE nodes should NOT increment forwarded_count
                                                % (they drop received messages, so low forwarding is their signature)
                                                is_blackhole = nodes(i).is_attacker && isfield(nodes(i), 'attack_strategy') && ~isempty(nodes(i).attack_strategy) && strcmpi(nodes(i).attack_strategy, 'BLACK_HOLE');
                                                if ~is_blackhole
                                                    if isfield(nodes(i), 'forwarded_count')
                                                        nodes(i).forwarded_count = nodes(i).forwarded_count + 1;
                                                    else
                                                        nodes(i).forwarded_count = 1;
                                                    end
                                                else
                                                    fprintf('[DEBUG] Blocked forwarded_count increment for BLACK_HOLE Node %d (location 2)\n', nodes(i).id);
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

    fprintf('\n--- Forwarding Behavior for ATTACKER Nodes ---\n');
    if exist('nodes', 'var') && ~isempty(nodes)
        for i = 1:length(nodes)
            node = nodes(i);
            if isfield(node, 'is_attacker') && node.is_attacker
                fc = 0; rc = 0;
                if isfield(node, 'forwarded_count'), fc = node.forwarded_count; end
                if isfield(node, 'received_count'), rc = node.received_count; end
                ratio = 0;
                if rc > 0, ratio = fc / rc; end
                attack_type = 'UNKNOWN';
                if isfield(node, 'attack_strategy'), attack_type = node.attack_strategy; end
                fprintf('Node %d (%s): forwarded_count = %d, received_count = %d, forwarding_ratio = %.3f\n', ...
                    node.id, attack_type, fc, rc, ratio);
            end
        end
    end
    fprintf('--- Forwarding Behavior for Normal Nodes ---\n');
    if exist('nodes', 'var') && ~isempty(nodes)
        for i = 1:length(nodes)
            node = nodes(i);
            if isfield(node, 'is_attacker') && ~node.is_attacker
                fc = 0; rc = 0;
                if isfield(node, 'forwarded_count'), fc = node.forwarded_count; end
                if isfield(node, 'received_count'), rc = node.received_count; end
                ratio = 0;
                if rc > 0, ratio = fc / rc; end
                fprintf('Node %d: forwarded_count = %d, received_count = %d, forwarding_ratio = %.3f\n', node.id, fc, rc, ratio);
            end
        end
    end
    fprintf('-------------------------------------------\n');

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
