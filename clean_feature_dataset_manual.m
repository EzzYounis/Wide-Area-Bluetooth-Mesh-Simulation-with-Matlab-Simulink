


% clean_feature_dataset_manual.m

% Delete all previously cleaned feature datasets (both balanced and non-balanced)
cleaned_files = dir('training_data/*_cleaned.csv');
for i = 1:length(cleaned_files)
	delete(fullfile(cleaned_files(i).folder, cleaned_files(i).name));
	fprintf('Deleted old cleaned file: %s\n', cleaned_files(i).name);
end

% Delete old merged/shuffled file if exists
if exist('training_data/merged_shuffled_feature_dataset.csv', 'file')
    delete('training_data/merged_shuffled_feature_dataset.csv');
    fprintf('Deleted old merged_shuffled_feature_dataset.csv\n');
end

% Batch process all balanced feature files
balanced_files = dir('training_data/balanced_feature_dataset_*.csv');
fprintf('\nProcessing %d balanced feature datasets...\n', length(balanced_files));

% Batch process all non-balanced feature files
feature_files = dir('training_data/feature_dataset_*.csv');
feature_files = feature_files(~contains({feature_files.name}, 'balanced')); % Exclude balanced ones
fprintf('Processing %d non-balanced feature datasets...\n', length(feature_files));

% Combine both file lists
files = [balanced_files; feature_files];
fprintf('\nTotal files to process: %d\n\n', length(files));

for k = 1:length(files)
	fname = fullfile(files(k).folder, files(k).name);
	data = readtable(fname);

	% --- Clean all features for FLOODING samples one by one with logical values ---
	row = strcmp(data.attack_type, 'FLOODING');
	if any(row)
		n = sum(row);
		% Timing features
		data.timing_regularity(row)        = 0.7 + 0.25*rand(n,1);  % HIGH (bursty CV pattern)
		data.message_frequency(row)        = 0.8 + 0.2*rand(n,1);   % Very high
		data.burst_intensity(row)          = 0.8 + 0.2*rand(n,1);   % Very high
		data.inter_arrival_variance(row)   = 0.7 + 0.2*rand(n,1);   % High (bursty)
		data.size_consistency(row)         = 0.8 + 0.2*rand(n,1);   % HIGH (consistent sizes)
		data.volume_anomaly_score(row)     = 0.7 + 0.3*rand(n,1);   % High
		% Content features
		data.message_length(row)           = 0.5 + 0.4*rand(n,1);   % Large messages
		data.entropy_score(row)            = 0.3 + 0.4*rand(n,1);   % Moderate (repetitive flooding)
		data.special_char_ratio(row)       = 0.1 + 0.2*rand(n,1);   % Low
		data.numeric_ratio(row)            = 0.2 + 0.3*rand(n,1);   % Low to moderate
		data.emergency_keyword_count(row)  = 0.05*rand(n,1);        % Very low
		data.suspicious_url_count(row)     = 0.05*rand(n,1);        % Low
		data.command_pattern_count(row)    = 0.05*rand(n,1);        % Low
		% Reputation features
		data.sender_reputation(row)        = 0.1 + 0.3*rand(n,1);   % Low (flooding = malicious)
		data.message_similarity_score(row) = 0.7 + 0.3*rand(n,1);   % High (repetitive messages)
		data.response_pattern(row)         = 0.2 + 0.3*rand(n,1);   % Low (no legitimate responses)
		data.interaction_diversity(row)    = 0.1 + 0.2*rand(n,1);   % Low (same pattern)
		data.temporal_consistency(row)     = 0.6 + 0.3*rand(n,1);   % Moderate-high (consistent timing)
		data.language_consistency(row)     = 0.5 + 0.3*rand(n,1);   % Moderate
		% Protocol features
		data.ttl_anomaly(row)              = 0.3 + 0.4*rand(n,1);   % Moderate (may be manipulated)
		data.sequence_gap_score(row)       = 0.2 + 0.3*rand(n,1);   % Low to moderate
		data.routing_anomaly(row)          = 0.4 + 0.3*rand(n,1);   % Moderate
		data.header_integrity(row)         = 0.8 + 0.2*rand(n,1);   % High
		data.encryption_consistency(row)   = 0.7 + 0.2*rand(n,1);   % High
		if ismember('protocol_compliance_score', data.Properties.VariableNames)
			data.protocol_compliance_score(row) = 0.9 + 0.1*rand(n,1);   % High
		elseif ismember('protocol_compliance', data.Properties.VariableNames)
			data.protocol_compliance(row) = 0.9 + 0.1*rand(n,1);   % High
		end
		% Resource & Network features
		if ismember('battery_impact_score', data.Properties.VariableNames)
			data.battery_impact_score(row) = 0.5 + 0.3*rand(n,1);   % Moderate-high
		elseif ismember('battery_impact', data.Properties.VariableNames)
			data.battery_impact(row) = 0.5 + 0.3*rand(n,1);   % Moderate-high
		end
		data.processing_load(row)          = 0.5 + 0.3*rand(n,1);   % Moderate-high
		data.memory_footprint(row)         = 0.5 + 0.3*rand(n,1);   % Moderate-high
		data.signal_strength_factor(row)   = 0.5 + 0.3*rand(n,1);   % Moderate
		data.mobility_pattern(row)         = 0.3 + 0.4*rand(n,1);   % Low to moderate
		data.emergency_context_score(row)  = 0.05*rand(n,1);        % Very low
		data.route_stability(row)          = 0.6 + 0.3*rand(n,1);   % Moderate
		data.forwarding_behavior(row)      = 0.5 + 0.3*rand(n,1);   % Moderate
		data.neighbor_trust_score(row)     = 0.3 + 0.4*rand(n,1);   % Low to moderate
		data.mesh_connectivity_health(row) = 0.6 + 0.3*rand(n,1);   % Moderate
		data.redundancy_factor(row)        = 0.5 + 0.3*rand(n,1);   % Moderate
	end

	% --- Clean all features for BLACK_HOLE samples one by one with logical values ---
	row = strcmp(data.attack_type, 'BLACK_HOLE');
	if any(row)
		n = sum(row);
		% Timing features: Normal to low activity
		data.timing_regularity(row)      = 0.2 + 0.3*rand(n,1);   % LOW-MODERATE (passive, not bursty)
		data.message_frequency(row)      = 0.2 + 0.4*rand(n,1);   % Low to moderate
		data.burst_intensity(row)        = 0.1 + 0.3*rand(n,1);   % Low
		data.inter_arrival_variance(row) = 0.3 + 0.4*rand(n,1);   % Moderate
		data.size_consistency(row)       = 0.5 + 0.3*rand(n,1);   % Moderate
		data.volume_anomaly_score(row)   = 0.3 + 0.4*rand(n,1);   % Moderate
		% Content features
		data.message_length(row)         = 0.2 + 0.5*rand(n,1);   % Low to moderate
		data.entropy_score(row)          = 0.4 + 0.4*rand(n,1);   % Moderate
		data.special_char_ratio(row)     = 0.2 + 0.3*rand(n,1);   % Low to moderate
		data.numeric_ratio(row)          = 0.2 + 0.3*rand(n,1);   % Low to moderate
		data.emergency_keyword_count(row)= 0.05*rand(n,1);        % Very low
		data.suspicious_url_count(row)   = 0.05*rand(n,1);        % Low
		data.command_pattern_count(row)  = 0.05*rand(n,1);        % Low
		% Reputation features
		data.sender_reputation(row)      = 0.3 + 0.4*rand(n,1);   % Moderate
		data.message_similarity_score(row) = 0.4 + 0.4*rand(n,1); % Moderate
		data.response_pattern(row)       = 0.2 + 0.3*rand(n,1);   % Low to moderate
		data.interaction_diversity(row)  = 0.3 + 0.4*rand(n,1);   % Moderate
		data.temporal_consistency(row)   = 0.4 + 0.4*rand(n,1);   % Moderate
		data.language_consistency(row)   = 0.5 + 0.3*rand(n,1);   % Moderate
		% Protocol features
		data.ttl_anomaly(row)            = 0.6 + 0.3*rand(n,1);   % Moderate-high (drops may affect TTL)
		data.sequence_gap_score(row)     = 0.4 + 0.3*rand(n,1);   % Moderate (drops cause gaps)
		data.routing_anomaly(row)        = 0.6 + 0.3*rand(n,1);   % Moderate-high (KEY SIGNATURE)
		data.header_integrity(row)       = 0.7 + 0.2*rand(n,1);   % High
		data.encryption_consistency(row) = 0.7 + 0.2*rand(n,1);   % High
		if ismember('protocol_compliance_score', data.Properties.VariableNames)
			data.protocol_compliance_score(row) = 0.8 + 0.2*rand(n,1);   % High
		elseif ismember('protocol_compliance', data.Properties.VariableNames)
			data.protocol_compliance(row) = 0.8 + 0.2*rand(n,1);   % High
		end
		% Resource & Network features: KEY SIGNATURE - Low forwarding
		if ismember('battery_impact_score', data.Properties.VariableNames)
			data.battery_impact_score(row) = 0.2 + 0.3*rand(n,1);   % Low
		elseif ismember('battery_impact', data.Properties.VariableNames)
			data.battery_impact(row) = 0.2 + 0.3*rand(n,1);   % Low
		end
		data.processing_load(row)        = 0.1 + 0.2*rand(n,1);   % Low (not processing forwarded packets)
		data.memory_footprint(row)       = 0.2 + 0.3*rand(n,1);   % Low
		data.signal_strength_factor(row) = 0.5 + 0.3*rand(n,1);   % Moderate
		data.mobility_pattern(row)       = 0.3 + 0.4*rand(n,1);   % Moderate
		data.emergency_context_score(row)= 0.05*rand(n,1);        % Very low
		data.route_stability(row)        = 0.1 + 0.3*rand(n,1);   % LOW (drops cause issues)
		data.forwarding_behavior(row)    = 0.0 + 0.15*rand(n,1);  % VERY LOW (drops packets! KEY SIGNATURE)
		data.neighbor_trust_score(row)   = 0.2 + 0.3*rand(n,1);   % Low (neighbors notice drops)
		data.mesh_connectivity_health(row) = 0.3 + 0.4*rand(n,1); % Low to moderate (affected by drops)
		data.redundancy_factor(row)      = 0.4 + 0.4*rand(n,1);   % Moderate (network compensates)
	end

	% --- Clean all features for SPOOFING samples one by one with logical values ---
	row = strcmp(data.attack_type, 'SPOOFING');
	if any(row)
		n = sum(row);
		% Timing features: Moderate activity
		data.timing_regularity(row)      = 0.2 + 0.4*rand(n,1);   % LOW-MODERATE (irregular)
		data.message_frequency(row)      = 0.1 + 0.3*rand(n,1);   % Moderate
		data.burst_intensity(row)        = 0.2 + 0.3*rand(n,1);   % Low to moderate
		data.inter_arrival_variance(row) = 0.4 + 0.3*rand(n,1);   % Moderate to high
		data.size_consistency(row)       = 0.4 + 0.3*rand(n,1);   % Moderate
		data.volume_anomaly_score(row)   = 0.3 + 0.3*rand(n,1);   % Moderate
		% Content features: HIGH SUSPICIOUS CONTENT (key signature)
		data.message_length(row)         = 0.3 + 0.4*rand(n,1);   % Moderate
		data.entropy_score(row)          = 0.5 + 0.3*rand(n,1);   % Moderate-high (varied malicious content)
		data.special_char_ratio(row)     = 0.5 + 0.4*rand(n,1);   % Moderate-high (malicious payloads)
		data.numeric_ratio(row)          = 0.4 + 0.3*rand(n,1);   % Moderate
		data.emergency_keyword_count(row)= 0.1 + 0.2*rand(n,1);   % Low (may fake emergency)
		data.suspicious_url_count(row)   = 0.6 + 0.4*rand(n,1);   % HIGH (KEY SIGNATURE)
		data.command_pattern_count(row)  = 0.5 + 0.4*rand(n,1);   % HIGH (KEY SIGNATURE)
		% Reputation features: Low from suspicious content
		data.sender_reputation(row)      = 0.1 + 0.3*rand(n,1);   % LOW (malicious content)
		data.message_similarity_score(row) = 0.3 + 0.4*rand(n,1); % Moderate (varied attacks)
		data.response_pattern(row)       = 0.3 + 0.3*rand(n,1);   % Moderate (may mimic responses)
		data.interaction_diversity(row)  = 0.4 + 0.4*rand(n,1);   % Moderate
		data.temporal_consistency(row)   = 0.3 + 0.4*rand(n,1);   % Moderate
		data.language_consistency(row)   = 0.4 + 0.4*rand(n,1);   % Moderate (may have inconsistencies)
		% Protocol features
		data.ttl_anomaly(row)            = 0.5 + 0.3*rand(n,1);   % Moderate-high (spoofed headers)
		data.sequence_gap_score(row)     = 0.4 + 0.3*rand(n,1);   % Moderate (spoofing may cause gaps)
		data.routing_anomaly(row)        = 0.5 + 0.3*rand(n,1);   % Moderate-high (spoofed sources)
		data.header_integrity(row)       = 0.6 + 0.3*rand(n,1);   % Moderate (may be forged)
		data.encryption_consistency(row) = 0.5 + 0.3*rand(n,1);   % Moderate (inconsistent encryption)
		if ismember('protocol_compliance_score', data.Properties.VariableNames)
			data.protocol_compliance_score(row) = 0.5 + 0.3*rand(n,1);   % Moderate
		elseif ismember('protocol_compliance', data.Properties.VariableNames)
			data.protocol_compliance(row) = 0.5 + 0.3*rand(n,1);   % Moderate
		end
		% Resource & Network features
		if ismember('battery_impact_score', data.Properties.VariableNames)
			data.battery_impact_score(row) = 0.3 + 0.3*rand(n,1);   % Moderate
		elseif ismember('battery_impact', data.Properties.VariableNames)
			data.battery_impact(row) = 0.3 + 0.3*rand(n,1);        % Moderate
		end
		data.processing_load(row)        = 0.3 + 0.3*rand(n,1);   % Moderate
		data.memory_footprint(row)       = 0.3 + 0.3*rand(n,1);   % Moderate
		data.signal_strength_factor(row) = 0.4 + 0.3*rand(n,1);   % Moderate
		data.mobility_pattern(row)       = 0.3 + 0.4*rand(n,1);   % Moderate
		data.emergency_context_score(row)= 0.1 + 0.2*rand(n,1);   % Low
		data.route_stability(row)        = 0.5 + 0.3*rand(n,1);   % Moderate
		data.forwarding_behavior(row)    = 0.4 + 0.3*rand(n,1);   % Moderate
		data.neighbor_trust_score(row)   = 0.2 + 0.3*rand(n,1);   % Low (untrusted content)
		data.mesh_connectivity_health(row) = 0.5 + 0.3*rand(n,1); % Moderate
		data.redundancy_factor(row)      = 0.5 + 0.3*rand(n,1);   % Moderate
	end

	% --- Clean all features for ADAPTIVE_FLOODING samples one by one with logical values ---
	row = strcmp(data.attack_type, 'ADAPTIVE_FLOODING');
	if any(row)
		n = sum(row);
		% Timing features: VERY HIGH activity with CONSISTENT burst patterns
		data.timing_regularity(row)      = 0.8 + 0.2*rand(n,1);   % VERY HIGH (consistent bursts)
		data.message_frequency(row)      = 0.8 + 0.2*rand(n,1);   % VERY HIGH
		data.burst_intensity(row)        = 0.8 + 0.2*rand(n,1);   % VERY HIGH
		data.inter_arrival_variance(row) = 0.7 + 0.2*rand(n,1);   % High but controlled
		data.size_consistency(row)       = 0.8 + 0.2*rand(n,1);   % High (consistent)
		data.volume_anomaly_score(row)   = 0.7 + 0.3*rand(n,1);   % High
		% Content features
		data.message_length(row)         = 0.5 + 0.3*rand(n,1);   % Moderate to large
		data.entropy_score(row)          = 0.4 + 0.3*rand(n,1);   % Moderate (appears normal)
		data.special_char_ratio(row)     = 0.2 + 0.3*rand(n,1);   % Low to moderate (appears legit)
		data.numeric_ratio(row)          = 0.3 + 0.3*rand(n,1);   % Moderate (appears normal)
		data.emergency_keyword_count(row)= 0.05*rand(n,1);        % Very low
		data.suspicious_url_count(row)   = 0.05*rand(n,1);        % Low (evades filters)
		data.command_pattern_count(row)  = 0.05*rand(n,1);        % Low
		% Reputation features: High (mimics legitimate)
		data.sender_reputation(row)      = 0.6 + 0.3*rand(n,1);   % Moderate-high (adaptive)
		data.message_similarity_score(row) = 0.6 + 0.3*rand(n,1); % Moderate-high (similar but varied)
		data.response_pattern(row)       = 0.5 + 0.3*rand(n,1);   % Moderate (mimics legitimate)
		data.interaction_diversity(row)  = 0.4 + 0.3*rand(n,1);   % Moderate
		data.temporal_consistency(row)   = 0.7 + 0.2*rand(n,1);   % High (consistent timing pattern)
		data.language_consistency(row)   = 0.7 + 0.2*rand(n,1);   % High (appears legitimate)
		% Protocol features
		data.ttl_anomaly(row)            = 0.2 + 0.3*rand(n,1);   % Low (adaptive, appears normal)
		data.sequence_gap_score(row)     = 0.2 + 0.3*rand(n,1);   % Low (well-formed)
		data.routing_anomaly(row)        = 0.3 + 0.3*rand(n,1);   % Low to moderate (adaptive)
		data.header_integrity(row)       = 0.9 + 0.1*rand(n,1);   % Very high
		data.encryption_consistency(row) = 0.8 + 0.2*rand(n,1);   % High (mimics legitimate)
		if ismember('protocol_compliance_score', data.Properties.VariableNames)
			data.protocol_compliance_score(row) = 0.9 + 0.1*rand(n,1);   % Very high
		elseif ismember('protocol_compliance', data.Properties.VariableNames)
			data.protocol_compliance(row) = 0.9 + 0.1*rand(n,1);   % Very high
		end
		% Resource & Network features
		if ismember('battery_impact_score', data.Properties.VariableNames)
			data.battery_impact_score(row) = 0.6 + 0.3*rand(n,1);   % Moderate-high
		elseif ismember('battery_impact', data.Properties.VariableNames)
			data.battery_impact(row) = 0.6 + 0.3*rand(n,1);        % Moderate-high
		end
		data.processing_load(row)        = 0.6 + 0.3*rand(n,1);   % Moderate-high
		data.memory_footprint(row)       = 0.6 + 0.3*rand(n,1);   % Moderate-high
		data.signal_strength_factor(row) = 0.6 + 0.3*rand(n,1);   % Moderate-high (good connectivity)
		data.mobility_pattern(row)       = 0.4 + 0.3*rand(n,1);   % Moderate
		data.emergency_context_score(row)= 0.05*rand(n,1);        % Very low
		data.route_stability(row)        = 0.7 + 0.2*rand(n,1);   % High (maintains stability)
		data.forwarding_behavior(row)    = 0.7 + 0.2*rand(n,1);   % High (appears normal)
		data.neighbor_trust_score(row)   = 0.6 + 0.3*rand(n,1);   % Moderate-high (appears legitimate)
		data.mesh_connectivity_health(row) = 0.7 + 0.2*rand(n,1); % High (well-connected)
		data.redundancy_factor(row)      = 0.6 + 0.3*rand(n,1);   % Moderate-high
	end

	% --- Clean all features for RESOURCE_EXHAUSTION samples one by one with logical values ---
	row = strcmp(data.attack_type, 'RESOURCE_EXHAUSTION');
	if any(row)
		n = sum(row);
		% Timing features: Moderate activity
		data.timing_regularity(row)      = 0.3 + 0.4*rand(n,1);   % MODERATE (steady pattern)
		data.message_frequency(row)      = 0.1 + 0.3*rand(n,1);   % Moderate
		data.burst_intensity(row)        = 0.3 + 0.3*rand(n,1);   % Moderate
		data.inter_arrival_variance(row) = 0.4 + 0.3*rand(n,1);   % Moderate
		data.size_consistency(row)       = 0.5 + 0.3*rand(n,1);   % Moderate
		data.volume_anomaly_score(row)   = 0.4 + 0.3*rand(n,1);   % Moderate
		% Content features: Large messages to exhaust resources (KEY SIGNATURE)
		data.message_length(row)         = 0.8 + 0.2*rand(n,1);   % VERY HIGH (large payloads)
		data.entropy_score(row)          = 0.5 + 0.3*rand(n,1);   % Moderate-high
		data.special_char_ratio(row)     = 0.3 + 0.3*rand(n,1);   % Moderate
		data.numeric_ratio(row)          = 0.3 + 0.3*rand(n,1);   % Moderate
		data.emergency_keyword_count(row)= 0.05*rand(n,1);        % Very low
		data.suspicious_url_count(row)   = 0.05*rand(n,1);        % Low
		data.command_pattern_count(row)  = 0.05*rand(n,1);        % Low
		% Reputation features
		data.sender_reputation(row)      = 0.3 + 0.4*rand(n,1);   % Moderate
		data.message_similarity_score(row) = 0.5 + 0.3*rand(n,1); % Moderate (repetitive resource drain)
		data.response_pattern(row)       = 0.3 + 0.3*rand(n,1);   % Moderate
		data.interaction_diversity(row)  = 0.3 + 0.3*rand(n,1);   % Moderate
		data.temporal_consistency(row)   = 0.5 + 0.3*rand(n,1);   % Moderate
		data.language_consistency(row)   = 0.6 + 0.3*rand(n,1);   % Moderate-high
		% Protocol features
		data.ttl_anomaly(row)            = 0.4 + 0.3*rand(n,1);   % Moderate
		data.sequence_gap_score(row)     = 0.3 + 0.3*rand(n,1);   % Moderate
		data.routing_anomaly(row)        = 0.4 + 0.3*rand(n,1);   % Moderate
		data.header_integrity(row)       = 0.7 + 0.2*rand(n,1);   % High
		data.encryption_consistency(row) = 0.7 + 0.2*rand(n,1);   % High
		if ismember('protocol_compliance_score', data.Properties.VariableNames)
			data.protocol_compliance_score(row) = 0.8 + 0.2*rand(n,1);   % High
		elseif ismember('protocol_compliance', data.Properties.VariableNames)
			data.protocol_compliance(row) = 0.8 + 0.2*rand(n,1);   % High
		end
		% Resource & Network features: KEY SIGNATURE - HIGH resource usage
		if ismember('battery_impact_score', data.Properties.VariableNames)
			data.battery_impact_score(row) = 0.7 + 0.3*rand(n,1);   % HIGH (drains battery, KEY SIGNATURE)
		elseif ismember('battery_impact', data.Properties.VariableNames)
			data.battery_impact(row) = 0.7 + 0.3*rand(n,1);        % HIGH (drains battery)
		end
		data.processing_load(row)        = 0.8 + 0.2*rand(n,1);   % VERY HIGH (KEY SIGNATURE)
		data.memory_footprint(row)       = 0.8 + 0.2*rand(n,1);   % VERY HIGH (KEY SIGNATURE)
		data.signal_strength_factor(row) = 0.5 + 0.3*rand(n,1);   % Moderate
		data.mobility_pattern(row)       = 0.3 + 0.4*rand(n,1);   % Moderate
		data.emergency_context_score(row)= 0.05*rand(n,1);        % Very low
		data.route_stability(row)        = 0.4 + 0.3*rand(n,1);   % Moderate (affected by resource strain)
		data.forwarding_behavior(row)    = 0.4 + 0.3*rand(n,1);   % Moderate
		data.neighbor_trust_score(row)   = 0.4 + 0.3*rand(n,1);   % Moderate
		data.mesh_connectivity_health(row) = 0.4 + 0.3*rand(n,1); % Moderate (affected by resources)
		data.redundancy_factor(row)      = 0.5 + 0.3*rand(n,1);   % Moderate
	end

	% --- Clean all features for NORMAL samples one by one with logical values ---
	row = strcmp(data.attack_type, 'NORMAL');
	if any(row)
		n = sum(row);
		% Timing features: LOW activity, IRREGULAR (realistic human patterns)
		data.timing_regularity(row)      = 0.0 + 0.3*rand(n,1);   % VERY LOW (irregular, realistic)
		data.message_frequency(row)      = 0.1 + 0.4*rand(n,1);   % LOW
		data.burst_intensity(row)        = 0.1 + 0.3*rand(n,1);   % LOW
		data.inter_arrival_variance(row) = 0.3 + 0.5*rand(n,1);   % MODERATE-HIGH (varies)
		data.size_consistency(row)       = 0.3 + 0.5*rand(n,1);   % MODERATE (varies)
		data.volume_anomaly_score(row)   = 0.1 + 0.3*rand(n,1);   % LOW
		% Content features: Normal content
		data.message_length(row)         = 0.2 + 0.5*rand(n,1);   % Small to moderate
		data.entropy_score(row)          = 0.4 + 0.4*rand(n,1);   % Moderate (natural text)
		data.special_char_ratio(row)     = 0.1 + 0.3*rand(n,1);   % Low (normal text)
		data.numeric_ratio(row)          = 0.2 + 0.3*rand(n,1);   % Low to moderate
		data.emergency_keyword_count(row)= 0.0 + 0.1*rand(n,1);   % Very low (occasional legitimate)
		data.suspicious_url_count(row)   = 0.02*rand(n,1);        % VERY LOW
		data.command_pattern_count(row)  = 0.02*rand(n,1);        % VERY LOW
		% Reputation features: HIGH but allow some variance (blended historical + message-based)
		data.sender_reputation(row)      = 0.5 + 0.4*rand(n,1);   % MODERATE-HIGH (0.5-0.9, reflects blending)
		data.message_similarity_score(row) = 0.3 + 0.5*rand(n,1); % Moderate (natural variation)
		data.response_pattern(row)       = 0.5 + 0.4*rand(n,1);   % Moderate-high (normal interactions)
		data.interaction_diversity(row)  = 0.5 + 0.4*rand(n,1);   % Moderate-high (varied interactions)
		data.temporal_consistency(row)   = 0.4 + 0.4*rand(n,1);   % Moderate (human patterns vary)
		data.language_consistency(row)   = 0.7 + 0.3*rand(n,1);   % High (consistent legitimate communication)
		% Protocol features
		data.ttl_anomaly(row)            = 0.1 + 0.3*rand(n,1);   % Low (normal routing)
		data.sequence_gap_score(row)     = 0.1 + 0.3*rand(n,1);   % Low (well-ordered)
		data.routing_anomaly(row)        = 0.1 + 0.3*rand(n,1);   % Low (normal routing)
		data.header_integrity(row)       = 0.9 + 0.1*rand(n,1);   % VERY HIGH
		data.encryption_consistency(row) = 0.8 + 0.2*rand(n,1);   % High (consistent legitimate encryption)
		if ismember('protocol_compliance_score', data.Properties.VariableNames)
			data.protocol_compliance_score(row) = 0.9 + 0.1*rand(n,1);   % VERY HIGH
		elseif ismember('protocol_compliance', data.Properties.VariableNames)
			data.protocol_compliance(row) = 0.9 + 0.1*rand(n,1);   % VERY HIGH
		end
		% Resource & Network features: Normal forwarding, low resource use
		if ismember('battery_impact_score', data.Properties.VariableNames)
			data.battery_impact_score(row) = 0.1 + 0.3*rand(n,1);   % LOW
		elseif ismember('battery_impact', data.Properties.VariableNames)
			data.battery_impact(row) = 0.1 + 0.3*rand(n,1);        % LOW
		end
		data.processing_load(row)        = 0.1 + 0.4*rand(n,1);   % Low to moderate (normal operations)
		data.memory_footprint(row)       = 0.1 + 0.4*rand(n,1);   % Low to moderate
		data.signal_strength_factor(row) = 0.5 + 0.4*rand(n,1);   % Moderate-high (normal connectivity)
		data.mobility_pattern(row)       = 0.3 + 0.5*rand(n,1);   % Moderate (varied mobility)
		data.emergency_context_score(row)= 0.0 + 0.1*rand(n,1);   % Very low (occasional legitimate)
		data.route_stability(row)        = 0.7 + 0.3*rand(n,1);   % HIGH
		data.forwarding_behavior(row)    = 0.4 + 0.4*rand(n,1);   % MODERATE (0.4-0.8, realistic)
		data.neighbor_trust_score(row)   = 0.6 + 0.3*rand(n,1);   % Moderate-high (trusted)
		data.mesh_connectivity_health(row) = 0.7 + 0.3*rand(n,1); % High (healthy network)
		data.redundancy_factor(row)      = 0.6 + 0.3*rand(n,1);   % Moderate-high (normal redundancy)
	end

	% Save the cleaned dataset
	[~, base, ext] = fileparts(fname);
	outname = fullfile(files(k).folder, [base '_cleaned' ext]);
	writetable(data, outname);
	fprintf('Cleaned file saved as %s\n', outname);
end

fprintf('\nManual cleaning complete for all feature files.\n');

%% Merge and Shuffle All Cleaned Datasets
fprintf('\n========================================\n');
fprintf('Merging and Shuffling All Cleaned Data\n');
fprintf('========================================\n\n');

% Load all cleaned files
cleaned_files = dir('training_data/*_cleaned.csv');
fprintf('Found %d cleaned files to merge\n', length(cleaned_files));

merged_data = table();
total_samples = 0;

for i = 1:length(cleaned_files)
    file_path = fullfile(cleaned_files(i).folder, cleaned_files(i).name);
    fprintf('Loading %d/%d: %s ... ', i, length(cleaned_files), cleaned_files(i).name);
    
    try
        current_data = readtable(file_path);
        
        % Ensure consistent columns
        if isempty(merged_data)
            merged_data = current_data;
        else
            common_cols = intersect(merged_data.Properties.VariableNames, ...
                                  current_data.Properties.VariableNames, 'stable');
            merged_data = [merged_data(:, common_cols); current_data(:, common_cols)];
        end
        
        fprintf('%d samples\n', height(current_data));
        total_samples = total_samples + height(current_data);
    catch ME
        fprintf('FAILED: %s\n', ME.message);
    end
end

fprintf('\nTotal samples merged: %d\n', total_samples);

% Shuffle the merged dataset
fprintf('Shuffling dataset... ');
rng(42); % Set random seed for reproducibility
shuffled_idx = randperm(height(merged_data));
shuffled_data = merged_data(shuffled_idx, :);
fprintf('Done\n');

% Save the merged and shuffled dataset
output_file = 'training_data/merged_shuffled_feature_dataset.csv';
writetable(shuffled_data, output_file);
fprintf('\nMerged and shuffled dataset saved to: %s\n', output_file);
fprintf('Total samples: %d\n', height(shuffled_data));

% Display class distribution
fprintf('\nClass Distribution:\n');
class_counts = groupcounts(shuffled_data, 'attack_type');
disp(class_counts);

fprintf('\n========================================\n');
fprintf('Cleaning, Merging, and Shuffling Complete!\n');
fprintf('========================================\n');
