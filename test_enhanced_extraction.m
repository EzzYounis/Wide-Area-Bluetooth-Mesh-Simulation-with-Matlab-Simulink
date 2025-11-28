%% Test Enhanced Message Extraction and Feature Calculations
% This script validates the improvements to message generation and feature extraction
% Author: Enhancement Validation
% Date: November 27, 2025

clear; clc;

fprintf('\n========================================\n');
fprintf('Testing Enhanced Message Extraction\n');
fprintf('========================================\n\n');

%% Test 1: SPOOFING Message Generation
fprintf('TEST 1: SPOOFING Content Generation\n');
fprintf('------------------------------------\n');

% Create a mock attacker node for spoofing
test_node_spoofing = struct();
test_node_spoofing.id = 999;
test_node_spoofing.attack_strategy = 'SPOOFING';
test_node_spoofing.last_attack_time = 0;

% Generate spoofing content (you'll need to copy the function or source it)
fprintf('Sample SPOOFING content would be generated here...\n');
fprintf('Expected features:\n');
fprintf('  - special_char_ratio: 0.30-0.50 (high)\n');
fprintf('  - emergency_keyword_count: 0.40-0.80 (high)\n');
fprintf('  - suspicious_url_count: 0.60-1.00 (very high)\n');
fprintf('  - command_pattern_count: 0.50-0.80 (moderate-high)\n\n');

%% Test 2: RESOURCE_EXHAUSTION Message Generation
fprintf('TEST 2: RESOURCE_EXHAUSTION Content Generation\n');
fprintf('--------------------------------------------\n');

test_node_resource = struct();
test_node_resource.id = 998;
test_node_resource.attack_strategy = 'RESOURCE_EXHAUSTION';
test_node_resource.attack_params = struct();
test_node_resource.attack_params.target_resource = 3; % CPU
test_node_resource.attack_params.exhaustion_rate = 0.8;

fprintf('Sample RESOURCE_EXHAUSTION content would be generated here...\n');
fprintf('Expected features:\n');
fprintf('  - message_length: 0.70-1.00 (very large)\n');
fprintf('  - command_pattern_count: 0.80-1.00 (very high)\n');
fprintf('  - special_char_ratio: 0.25-0.40 (moderate-high)\n');
fprintf('  - resource_utilization: 0.80-1.00 (very high)\n\n');

%% Test 3: Feature Extraction Functions
fprintf('TEST 3: Feature Extraction Function Tests\n');
fprintf('------------------------------------------\n');

% Test calculateSpecialCharRatio
test_texts = {
    'Normal message with few special chars.',
    '!!! URGENT !!! Emergency @ https://fake.com?token=ABC123 !!!',
    '$$$ CRITICAL $$$ Action required!!! Visit @@@website@@@ NOW!!!'
};

fprintf('\nSpecial Character Ratio Tests:\n');
for i = 1:length(test_texts)
    ratio = testCalculateSpecialCharRatio(test_texts{i});
    fprintf('  Text %d: %.4f - "%s"\n', i, ratio, test_texts{i}(1:min(60, length(test_texts{i}))));
end

% Test countEmergencyKeywords
fprintf('\nEmergency Keyword Tests:\n');
for i = 1:length(test_texts)
    count = testCountEmergencyKeywords(test_texts{i});
    fprintf('  Text %d: %.4f - "%s"\n', i, count, test_texts{i}(1:min(60, length(test_texts{i}))));
end

% Test countSuspiciousURLs
test_url_texts = {
    'Normal message with no URLs',
    'Visit https://fake.com for more info',
    'URGENT! Visit https://fake.com?token=ABC&verify=NOW&emergency=TRUE !!!'
};

fprintf('\nSuspicious URL Tests:\n');
for i = 1:length(test_url_texts)
    count = testCountSuspiciousURLs(test_url_texts{i});
    fprintf('  Text %d: %.4f - "%s"\n', i, count, test_url_texts{i}(1:min(60, length(test_url_texts{i}))));
end

% Test countCommandPatterns
test_cmd_texts = {
    'Normal message about system status',
    'Please delete the old files',
    'exec BATTERY_VAMPIRE! sudo python crypto_burn.py --infinite && kill -9 power_save!'
};

fprintf('\nCommand Pattern Tests:\n');
for i = 1:length(test_cmd_texts)
    count = testCountCommandPatterns(test_cmd_texts{i});
    fprintf('  Text %d: %.4f - "%s"\n', i, count, test_cmd_texts{i}(1:min(60, length(test_cmd_texts{i}))));
end

%% Test 4: Entropy Calculation
fprintf('\nEntropy Tests:\n');
test_entropy_texts = {
    'The quick brown fox jumps over the lazy dog',
    'URGENT URGENT URGENT URGENT URGENT URGENT',
    '!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!',
    'Mixed content with repeated URGENT URGENT CRITICAL CRITICAL words'
};

for i = 1:length(test_entropy_texts)
    entropy = testCalculateEntropy(test_entropy_texts{i});
    fprintf('  Text %d: %.4f - "%s"\n', i, entropy, test_entropy_texts{i}(1:min(60, length(test_entropy_texts{i}))));
end

fprintf('\n========================================\n');
fprintf('Enhancement Validation Complete\n');
fprintf('========================================\n\n');

fprintf('NEXT STEPS:\n');
fprintf('1. Run simulateMeshIDS.m to test in full simulation\n');
fprintf('2. Review debug output for actual feature values\n');
fprintf('3. Run validateModels.m to check detection rates\n');
fprintf('4. Compare before/after metrics\n\n');

%% Helper Functions (Simplified versions for testing)

function ratio = testCalculateSpecialCharRatio(text)
    if isempty(text)
        ratio = 0;
        return;
    end
    
    is_letter = isletter(text);
    is_digit = (text >= '0' & text <= '9');
    is_space = (text == ' ');
    is_special = ~(is_letter | is_digit | is_space);
    
    % Count high-suspicion characters
    suspicious_chars = '!@#$%^&*=+|\<>[]{}();''\"';
    high_suspicion_count = 0;
    for i = 1:length(suspicious_chars)
        high_suspicion_count = high_suspicion_count + sum(text == suspicious_chars(i));
    end
    
    base_ratio = sum(is_special) / length(text);
    suspicious_bonus = min(0.3, high_suspicion_count / length(text));
    ratio = min(1.0, base_ratio + suspicious_bonus);
end

function count = testCountEmergencyKeywords(text)
    keywords = {'urgent', 'emergency', 'critical', 'help', 'alert', 'breaking', 'immediate'};
    text_lower = lower(text);
    
    raw_count = 0;
    for i = 1:length(keywords)
        occurrences = length(strfind(text_lower, keywords{i}));
        raw_count = raw_count + occurrences;
        if occurrences > 1
            raw_count = raw_count + (occurrences - 1) * 0.4; % Repetition bonus
        end
    end
    
    count = min(1, raw_count / 6);
end

function count = testCountSuspiciousURLs(text)
    text_lower = lower(text);
    count = 0;
    
    % Basic URLs
    if contains(text_lower, 'http://') || contains(text_lower, 'https://') || contains(text_lower, 'www.')
        count = count + 1;
    end
    
    % Suspicious parameters
    params = {'?token=', '?auth=', '?verify=', '?urgent=', '?emergency=', '?exec='};
    for i = 1:length(params)
        if contains(text_lower, params{i})
            count = count + 1.5;
        end
    end
    
    % HTTPS bonus
    https_count = length(strfind(text_lower, 'https://'));
    count = count + https_count * 1.2;
    
    % Emergency + URL
    emergency_words = {'urgent', 'emergency', 'critical'};
    has_emergency = false;
    for i = 1:length(emergency_words)
        if contains(text_lower, emergency_words{i})
            has_emergency = true;
            break;
        end
    end
    if has_emergency && count > 0
        count = count + 2;
    end
end

function count = testCountCommandPatterns(text)
    text_lower = lower(text);
    count = 0;
    
    % High-risk commands
    high_risk = {'exec', 'sudo', 'system(', 'bash -c', 'python -c', 'rm -rf', 'kill -', 'malloc'};
    for i = 1:length(high_risk)
        occurrences = length(strfind(text_lower, high_risk{i}));
        count = count + occurrences * 2.5;
    end
    
    % Execution patterns
    exec_patterns = {'$(', '&&', '||', '; do ', 'exec(', 'eval('};
    for i = 1:length(exec_patterns)
        if contains(text, exec_patterns{i})
            count = count + 2.0;
        end
    end
    
    count = min(count / 8, 1);
end

function entropy = testCalculateEntropy(text)
    if isempty(text)
        entropy = 0;
        return;
    end
    
    [~, ~, idx] = unique(text);
    counts = accumarray(idx, 1);
    probabilities = counts / length(text);
    raw_entropy = -sum(probabilities .* log2(probabilities + eps));
    base_entropy = min(1, raw_entropy / 8.0);
    
    % Repetition penalty
    if length(text) > 50
        max_char_count = max(counts);
        repetition_ratio = max_char_count / length(text);
        
        if repetition_ratio > 0.15
            repetition_penalty = (repetition_ratio - 0.15) * 0.5;
            base_entropy = base_entropy * (1 - repetition_penalty);
        end
        
        words = strsplit(lower(text));
        if length(words) > 5
            unique_words = unique(words);
            word_repetition = 1 - (length(unique_words) / length(words));
            if word_repetition > 0.3
                base_entropy = base_entropy * 0.85;
            end
        end
    end
    
    entropy = max(0, min(1, base_entropy));
end
