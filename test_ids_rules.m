%% Quick self-test for rule-based disambiguation (Flooding vs Resource Exhaustion)
% Uses the feature vector from the log to ensure FLOODING is preferred
% when volume anomaly and message size are very high.

clear; clc;

% Feature vector from the user's log (43 features)
features = [
    0.3000 0.6250 0.3000 0.8167 0.7000 0.3000 0.0000 1.0000 0.5748 0.1410 ...
    0.0356 0.1250 0.0000 0.3000 1.0000 0.3612 0.1305 0.3264 0.0670 1.0000 ...
    0.0046 1.0000 0.0000 0.1000 0.6388 0.6588 0.0000 0.0000 0.0000 1.0000 ...
    1.0000 1.0000 0.1880 1.0000 0.0064 0.7000 0.0000 0.0000 0.8000 0.0000 ...
    0.0046 0.8000 0.0000 ];

% Minimal node struct to call rule-based detection
node = struct();
node.ids_model = struct();
node.ids_model.rules = createDetectionRules();

% Call the rule-based detector from simulateMeshIDS.m if available
try
    [rule_result] = runRuleBasedDetection(node, struct('id','MSG_000031'), [], 0, features);
    fprintf('Detected attacks: %s\n', strjoin(rule_result.detected_attacks, ', '));
    fprintf('Confidences: %s\n', strjoin(arrayfun(@(x) sprintf('%.2f', x), rule_result.confidences, 'UniformOutput', false), ', '));
    fprintf('Primary: %s (conf=%.2f)\n', rule_result.primary_attack, rule_result.overall_confidence);
catch ME
    fprintf('Self-test could not run: %s\n', ME.message);
    fprintf('Make sure this script runs in the same context as simulateMeshIDS.m\n');
end

function rules = createDetectionRules()
% Lightweight copy to run in isolation if simulateMeshIDS.m is not loaded
rules = struct();
rules.flooding = struct('message_freq_threshold',0.35,'message_size_threshold',0.6,'burst_window',60,'confidence',0.7);
rules.spoofing = struct('suspicious_url_count',4,'emergency_keyword_abuse',10,'sender_reputation_threshold',0.1,'confidence',0.85);
rules.resource_exhaustion = struct('message_size_threshold',0.9,'frequency_threshold',0.85,'battery_impact_threshold',0.95,'confidence',0.6);
rules.black_hole = struct('forwarding_threshold',0.05,'routing_anomaly_threshold',0.8,'confidence',0.75);
end