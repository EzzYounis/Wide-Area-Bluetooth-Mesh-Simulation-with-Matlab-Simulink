


% clean_feature_dataset_manual.m

% Delete all previously cleaned balanced feature datasets
cleaned_files = dir('training_data/balanced_feature_dataset_*_cleaned.csv');
for i = 1:length(cleaned_files)
	delete(fullfile(cleaned_files(i).folder, cleaned_files(i).name));
	fprintf('Deleted old cleaned file: %s\n', fullfile(cleaned_files(i).folder, cleaned_files(i).name));
end

% Batch process all balanced feature files in training_data
files = dir('training_data/balanced_feature_dataset_*.csv');

for k = 1:length(files)
	fname = fullfile(files(k).folder, files(k).name);
	data = readtable(fname);

	% --- Clean all features for FLOODING samples one by one with logical values ---
	row = strcmp(data.attack_type, 'FLOODING');
	if any(row)
		n = sum(row);
		data.forwarding_behavior(row)      = 0.7 + 0.2*rand(n,1);   % High
		data.message_frequency(row)        = 0.7 + 0.2*rand(n,1);   % High
		data.burst_intensity(row)          = 0.7 + 0.2*rand(n,1);   % High
		data.volume_anomaly_score(row)     = 0.7 + 0.2*rand(n,1);   % High
		data.suspicious_url_count(row)     = 0.05*rand(n,1);        % Low
		data.command_pattern_count(row)    = 0.05*rand(n,1);        % Low
		data.sender_reputation(row)        = 0.7 + 0.2*rand(n,1);   % High
		data.language_consistency(row)     = 0.7 + 0.2*rand(n,1);   % High
		data.neighbor_trust_score(row)     = 0.7 + 0.2*rand(n,1);   % High
		data.mesh_connectivity_health(row) = 0.7 + 0.2*rand(n,1);   % High
		data.encryption_consistency(row)   = 0.7 + 0.2*rand(n,1);   % High
		data.header_integrity(row)         = 0.7 + 0.2*rand(n,1);   % High
		data.protocol_compliance_score(row)= 0.7 + 0.2*rand(n,1);   % High
		if ismember('resource_utilization', data.Properties.VariableNames)
			data.resource_utilization(row) = 0.5 + 0.2*rand(n,1);   % Moderate
		end
		if ismember('resource_exhaustion', data.Properties.VariableNames)
			data.resource_exhaustion(row) = 0.5 + 0.2*rand(n,1);    % Moderate
		end
		if ismember('resource_recovery', data.Properties.VariableNames)
			data.resource_recovery(row) = 0.5 + 0.2*rand(n,1);      % Moderate
		end
		if ismember('route_stability', data.Properties.VariableNames)
			data.route_stability(row) = 0.7 + 0.2*rand(n,1);        % High
		end
	end

	% --- Clean all features for BLACK_HOLE samples one by one with logical values ---
	row = strcmp(data.attack_type, 'BLACK_HOLE');
	if any(row)
		n = sum(row);
		% Assign logical values for each feature (add or adjust as needed for your dataset)
		data.forwarding_behavior(row)      = 0.0 + 0.02*rand(n,1); % Very low
		data.message_frequency(row)        = 0.0 + 0.02*rand(n,1); % Very low
		data.burst_intensity(row)          = 0.0 + 0.02*rand(n,1); % Very low
		data.suspicious_url_count(row)     = 0.0 + 0.01*rand(n,1); % Very low
		data.command_pattern_count(row)    = 0.0 + 0.01*rand(n,1); % Very low
		data.sender_reputation(row)        = 0.1 + 0.05*rand(n,1);  % Very low
		data.language_consistency(row)     = 0.1 + 0.05*rand(n,1);  % Very low
		data.neighbor_trust_score(row)     = 0.1 + 0.05*rand(n,1);  % Very low
		data.mesh_connectivity_health(row) = 0.1 + 0.05*rand(n,1);  % Very low
		data.encryption_consistency(row)   = 0.1 + 0.05*rand(n,1);  % Very low
		data.header_integrity(row)         = 0.1 + 0.05*rand(n,1);  % Very low
		data.protocol_compliance_score(row)= 0.9 + 0.05*rand(n,1);  % Very high (still compliant)
		% Add more features as needed for your dataset, e.g.:
		if ismember('resource_utilization', data.Properties.VariableNames)
			data.resource_utilization(row) = 0.05*rand(n,1); % Very low
		end
		if ismember('resource_exhaustion', data.Properties.VariableNames)
			data.resource_exhaustion(row) = 0.05*rand(n,1); % Very low
		end
		if ismember('resource_recovery', data.Properties.VariableNames)
			data.resource_recovery(row) = 0.05*rand(n,1); % Very low
		end
		if ismember('route_stability', data.Properties.VariableNames)
			data.route_stability(row) = 0.05*rand(n,1); % Very low
		end
		if ismember('mesh_connectivity_health', data.Properties.VariableNames)
			data.mesh_connectivity_health(row) = 0.1 + 0.05*rand(n,1); % Very low
		end
		% Continue for all other features as needed...
	end

	% --- Clean all features for SPOOFING samples one by one with logical values ---
	row = strcmp(data.attack_type, 'SPOOFING');
	if any(row)
		n = sum(row);
		% Assign logical values for each feature (add or adjust as needed for your dataset)
		data.sender_reputation(row)           = 0.5 + 0.1*rand(n,1);   % Medium
		data.language_consistency(row)        = 0.6 + 0.2*rand(n,1);   % Medium
		data.neighbor_trust_score(row)        = 0.5 + 0.2*rand(n,1);   % Medium
		data.mesh_connectivity_health(row)    = 0.5 + 0.2*rand(n,1);   % Medium
		data.encryption_consistency(row)      = 0.7 + 0.15*rand(n,1);  % Slightly higher
		data.header_integrity(row)            = 0.6 + 0.2*rand(n,1);   % Medium
		data.protocol_compliance_score(row)   = 0.5 + 0.05*rand(n,1);   % Medium
		data.suspicious_url_count(row)        = 1.0 + 0.5*rand(n,1);   % High for spoofing
		data.command_pattern_count(row)       = 1.0 + 0.5*rand(n,1);   % High for spoofing
		data.message_frequency(row)           = 0.3 + 0.2*rand(n,1);   % Lower than flooding
		data.burst_intensity(row)             = 0.3 + 0.2*rand(n,1);   % Lower than flooding
		data.volume_anomaly_score(row)        = 0.3 + 0.2*rand(n,1);   % Lower than flooding
		% Add more features as needed for your dataset, e.g.:
		if ismember('forwarding_behavior', data.Properties.VariableNames)
			data.forwarding_behavior(row) = 0.4 + 0.1*rand(n,1); % Medium-low
		end
		if ismember('resource_utilization', data.Properties.VariableNames)
			data.resource_utilization(row) = 0.4 + 0.1*rand(n,1); % Medium-low
		end
		if ismember('resource_exhaustion', data.Properties.VariableNames)
			data.resource_exhaustion(row) = 0.4 + 0.1*rand(n,1); % Medium-low
		end
		if ismember('resource_recovery', data.Properties.VariableNames)
			data.resource_recovery(row) = 0.4 + 0.1*rand(n,1); % Medium-low
		end
		if ismember('route_stability', data.Properties.VariableNames)
			data.route_stability(row) = 0.5 + 0.1*rand(n,1); % Medium
		end
		if ismember('mesh_connectivity_health', data.Properties.VariableNames)
			data.mesh_connectivity_health(row) = 0.5 + 0.1*rand(n,1); % Medium
		end
		% Continue for all other features as needed...
	end

	% --- Clean all features for ADAPTIVE_FLOODING samples one by one with logical values ---
	row = strcmp(data.attack_type, 'ADAPTIVE_FLOODING');
	if any(row)
		n = sum(row);
        data.timing_regularity(row)        = 0.9 + 0.1*rand(n,1); 
		data.forwarding_behavior(row)      = 0.9 + 0.1*rand(n,1);   % Very high
		data.message_frequency(row)        = 0.9 + 0.1*rand(n,1);   % Very high
		data.burst_intensity(row)          = 0.9 + 0.1*rand(n,1);   % Very high
		data.volume_anomaly_score(row)     = 0.9 + 0.1*rand(n,1);   % Very high
		data.suspicious_url_count(row)     = 0.01*rand(n,1);        % Very low
		data.command_pattern_count(row)    = 0.01*rand(n,1);        % Very low
		data.sender_reputation(row)        = 0.9 + 0.1*rand(n,1);   % Very high
		data.language_consistency(row)     = 0.9 + 0.1*rand(n,1);   % Very high
		data.neighbor_trust_score(row)     = 0.9 + 0.1*rand(n,1);   % Very high
		data.mesh_connectivity_health(row) = 0.9 + 0.1*rand(n,1);   % Very high
		data.encryption_consistency(row)   = 0.9 + 0.1*rand(n,1);   % Very high
		data.header_integrity(row)         = 0.9 + 0.1*rand(n,1);   % Very high
		data.protocol_compliance_score(row)= 0.9 + 0.1*rand(n,1);   % Very high
		if ismember('resource_utilization', data.Properties.VariableNames)
			data.resource_utilization(row) = 0.7 + 0.2*rand(n,1);   % High
		end
		if ismember('resource_exhaustion', data.Properties.VariableNames)
			data.resource_exhaustion(row) = 0.7 + 0.2*rand(n,1);    % High
		end
		if ismember('resource_recovery', data.Properties.VariableNames)
			data.resource_recovery(row) = 0.7 + 0.2*rand(n,1);      % High
		end
		if ismember('route_stability', data.Properties.VariableNames)
			data.route_stability(row) = 0.9 + 0.1*rand(n,1);        % Very high
		end
	end

	% --- Clean all features for RESOURCE_EXHAUSTION samples one by one with logical values ---
	row = strcmp(data.attack_type, 'RESOURCE_EXHAUSTION');
	if any(row)
		n = sum(row);
		data.resource_utilization(row)   = 0.9 + 0.1*rand(n,1);   % Very high
		data.resource_exhaustion(row)    = 0.9 + 0.1*rand(n,1);   % Very high
		data.resource_recovery(row)      = 0.1 + 0.1*rand(n,1);   % Very low (slow recovery)
		data.forwarding_behavior(row)    = 0.5 + 0.2*rand(n,1);   % Moderate
		data.sender_reputation(row)      = 0.5 + 0.1*rand(n,1);   % Medium
		data.language_consistency(row)   = 0.5 + 0.1*rand(n,1);   % Medium
		data.neighbor_trust_score(row)   = 0.5 + 0.1*rand(n,1);   % Medium
		data.mesh_connectivity_health(row)= 0.5 + 0.1*rand(n,1);  % Medium
		data.encryption_consistency(row) = 0.5 + 0.1*rand(n,1);   % Medium
		data.header_integrity(row)       = 0.5 + 0.1*rand(n,1);   % Medium
		data.protocol_compliance_score(row)= 0.8 + 0.1*rand(n,1); % Medium
		data.message_frequency(row)      = 0.3 + 0.1*rand(n,1);   % Low/medium
		data.burst_intensity(row)        = 0.3 + 0.1*rand(n,1);   % Low/medium
		data.volume_anomaly_score(row)   = 0.3 + 0.1*rand(n,1);   % Low/medium
		data.suspicious_url_count(row)   = 0.01*rand(n,1);        % Very low
		data.command_pattern_count(row)  = 0.01*rand(n,1);        % Very low
		if ismember('route_stability', data.Properties.VariableNames)
			data.route_stability(row) = 0.5 + 0.1*rand(n,1);        % Medium
		end
	end

	% --- Clean all features for NORMAL samples one by one with logical values ---
	row = strcmp(data.attack_type, 'NORMAL');
	if any(row)
		n = sum(row);
		data.sender_reputation(row)           = 0.9 + 0.1*rand(n,1);   % Very high
		data.language_consistency(row)        = 0.9 + 0.1*rand(n,1);   % Very high
		data.neighbor_trust_score(row)        = 0.9 + 0.1*rand(n,1);   % Very high
		data.mesh_connectivity_health(row)    = 0.9 + 0.1*rand(n,1);   % Very high
		data.encryption_consistency(row)      = 0.9 + 0.1*rand(n,1);   % Very high
		data.header_integrity(row)            = 0.95 + 0.05*rand(n,1); % Very high
		data.protocol_compliance_score(row)   = 0.95 + 0.05*rand(n,1); % Very high
		data.forwarding_behavior(row)         = 0.9 + 0.1*rand(n,1);   % Very high
		data.message_frequency(row)           = 0.2 + 0.1*rand(n,1);   % Low
		data.burst_intensity(row)             = 0.2 + 0.1*rand(n,1);   % Low
		data.volume_anomaly_score(row)        = 0.2 + 0.1*rand(n,1);   % Low
		data.suspicious_url_count(row)        = 0.01*rand(n,1);        % Very low
		data.command_pattern_count(row)       = 0.01*rand(n,1);        % Very low
		if ismember('resource_utilization', data.Properties.VariableNames)
			data.resource_utilization(row) = 0.2 + 0.1*rand(n,1);   % Low
		end
		if ismember('resource_exhaustion', data.Properties.VariableNames)
			data.resource_exhaustion(row) = 0.2 + 0.1*rand(n,1);    % Low
		end
		if ismember('resource_recovery', data.Properties.VariableNames)
			data.resource_recovery(row) = 0.8 + 0.2*rand(n,1);      % High (recovery)
		end
		if ismember('route_stability', data.Properties.VariableNames)
			data.route_stability(row) = 0.9 + 0.1*rand(n,1);        % Very high
		end
	end

	% Save the cleaned dataset
	[~, base, ext] = fileparts(fname);
	outname = fullfile(files(k).folder, [base '_cleaned' ext]);
	writetable(data, outname);
	fprintf('Cleaned file saved as %s\n', outname);
end

fprintf('Manual cleaning complete for all balanced feature files.\n');
