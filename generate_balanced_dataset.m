% Generate Balanced Dataset - Create synthetic data to reach 200,000 total samples
% This script will generate missing data for each attack type to balance the dataset

clear; clc;

% Configuration
TARGET_TOTAL = 200000;
INPUT_FILE = 'training_data/merged_shuffled_feature_dataset.csv';
OUTPUT_FILE = 'training_data/balanced_feature_dataset.csv';

fprintf('=== Balanced Dataset Generator ===\n\n');

% Load existing data
if ~exist(INPUT_FILE, 'file')
    error('Input file not found: %s', INPUT_FILE);
end

fprintf('Loading existing data...\n');
existingData = readtable(INPUT_FILE);
fprintf('Loaded %d samples\n\n', height(existingData));

% Get current distribution
currentDist = groupcounts(existingData, 'attack_type');
disp('Current Distribution:');
disp(currentDist);

% Calculate target samples per class (equal distribution)
attackTypes = unique(existingData.attack_type);
numClasses = length(attackTypes);
targetPerClass = floor(TARGET_TOTAL / numClasses);

fprintf('\n=== Generation Plan ===\n');
fprintf('Target total samples: %d\n', TARGET_TOTAL);
fprintf('Number of classes: %d\n', numClasses);
fprintf('Target per class: %d\n\n', targetPerClass);

% Calculate how many samples to generate for each class
generationPlan = table();
for i = 1:height(currentDist)
    attackType = currentDist.attack_type{i};
    currentCount = currentDist.GroupCount(i);
    toGenerate = targetPerClass - currentCount;
    
    generationPlan = [generationPlan; table({attackType}, currentCount, toGenerate, ...
        'VariableNames', {'AttackType', 'Current', 'ToGenerate'})];
    
    fprintf('%s: Current=%d, ToGenerate=%d\n', attackType, currentCount, toGenerate);
end

% Get feature names (exclude attack_type and non-numeric columns)
allNames = existingData.Properties.VariableNames;
featureNames = {};
for i = 1:length(allNames)
    varName = allNames{i};
    % Only include numeric columns, exclude attack_type and message_id
    if isnumeric(existingData.(varName)) && ~strcmp(varName, 'attack_type')
        featureNames{end+1} = varName;
    end
end
fprintf('Using %d numeric features for generation\n', length(featureNames));

fprintf('\n=== Starting Data Generation ===\n');
generatedData = table();

for i = 1:height(generationPlan)
    attackType = generationPlan.AttackType{i};
    toGenerate = generationPlan.ToGenerate(i);
    
    if toGenerate <= 0
        fprintf('%s: No generation needed\n', attackType);
        continue;
    end
    
    fprintf('\nGenerating %d samples for %s...\n', toGenerate, attackType);
    
    % Get existing samples for this attack type
    classData = existingData(strcmp(existingData.attack_type, attackType), :);
    
    if height(classData) < 10
        warning('Very few samples for %s. Generation may not be accurate.', attackType);
    end
    
    % Calculate statistics for each feature
    featureStats = struct();
    for j = 1:length(featureNames)
        featureName = featureNames{j};
        values = classData.(featureName);
        
        featureStats.(featureName).mean = mean(values);
        featureStats.(featureName).std = std(values);
        featureStats.(featureName).min = min(values);
        featureStats.(featureName).max = max(values);
        featureStats.(featureName).median = median(values);
        featureStats.(featureName).q25 = quantile(values, 0.25);
        featureStats.(featureName).q75 = quantile(values, 0.75);
    end
    
    % Generate synthetic samples
    newSamples = table();
    
    % Use multiple generation strategies for diversity
    numFromNoise = floor(toGenerate * 0.4);  % 40% from Gaussian noise
    numFromJitter = floor(toGenerate * 0.4); % 40% from jittered copies
    numFromInterp = toGenerate - numFromNoise - numFromJitter; % 20% from interpolation
    
    % Strategy 1: Gaussian noise based on statistics
    for k = 1:numFromNoise
        newRow = table();
        
        % Handle non-numeric columns first
        if ismember('message_id', existingData.Properties.VariableNames)
            newRow.message_id = {sprintf('SYNTH_%s_%06d', attackType, k)};
        end
        
        % Generate numeric features
        for j = 1:length(featureNames)
            featureName = featureNames{j};
            stats = featureStats.(featureName);
            
            % Generate value with Gaussian noise
            value = stats.mean + stats.std * randn();
            
            % Clip to observed range
            value = max(stats.min, min(stats.max, value));
            
            newRow.(featureName) = value;
        end
        newRow.attack_type = {attackType};
        newSamples = [newSamples; newRow];
    end
    
    % Strategy 2: Jittered copies of existing samples
    for k = 1:numFromJitter
        % Pick a random existing sample
        idx = randi(height(classData));
        newRow = classData(idx, :);
        
        % Update message_id if it exists
        if ismember('message_id', existingData.Properties.VariableNames)
            newRow.message_id = {sprintf('SYNTH_%s_%06d', attackType, numFromNoise + k)};
        end
        
        % Add small jitter to numeric features (5% noise)
        for j = 1:length(featureNames)
            featureName = featureNames{j};
            originalValue = newRow.(featureName);
            stats = featureStats.(featureName);
            
            % Add jitter (5% of standard deviation)
            jitter = 0.05 * stats.std * randn();
            value = originalValue + jitter;
            
            % Clip to observed range
            value = max(stats.min, min(stats.max, value));
            
            newRow.(featureName) = value;
        end
        
        newSamples = [newSamples; newRow];
    end
    
    % Strategy 3: Interpolation between existing samples
    for k = 1:numFromInterp
        % Pick two random existing samples
        idx1 = randi(height(classData));
        idx2 = randi(height(classData));
        
        % Random interpolation weight
        alpha = rand();
        
        newRow = table();
        
        % Handle non-numeric columns
        if ismember('message_id', existingData.Properties.VariableNames)
            newRow.message_id = {sprintf('SYNTH_%s_%06d', attackType, numFromNoise + numFromJitter + k)};
        end
        
        for j = 1:length(featureNames)
            featureName = featureNames{j};
            value1 = classData.(featureName)(idx1);
            value2 = classData.(featureName)(idx2);
            
            % Interpolate
            value = alpha * value1 + (1 - alpha) * value2;
            
            newRow.(featureName) = value;
        end
        newRow.attack_type = {attackType};
        
        newSamples = [newSamples; newRow];
    end
    
    generatedData = [generatedData; newSamples];
    fprintf('Generated %d samples for %s\n', height(newSamples), attackType);
end

% Combine existing and generated data
fprintf('\n=== Combining Data ===\n');
balancedData = [existingData; generatedData];

fprintf('Original data: %d samples\n', height(existingData));
fprintf('Generated data: %d samples\n', height(generatedData));
fprintf('Combined data: %d samples\n', height(balancedData));

% Shuffle the combined dataset
fprintf('\nShuffling combined dataset...\n');
rng(42); % For reproducibility
shuffleIdx = randperm(height(balancedData));
balancedData = balancedData(shuffleIdx, :);

% Show final distribution
fprintf('\n=== Final Distribution ===\n');
finalDist = groupcounts(balancedData, 'attack_type');
disp(finalDist);

% Save the balanced dataset
fprintf('\nSaving balanced dataset to: %s\n', OUTPUT_FILE);
writetable(balancedData, OUTPUT_FILE);

fprintf('\n=== Generation Complete ===\n');
fprintf('Total samples: %d\n', height(balancedData));
fprintf('Target was: %d\n', TARGET_TOTAL);
fprintf('Output saved to: %s\n', OUTPUT_FILE);

% Show summary statistics
fprintf('\n=== Summary ===\n');
for i = 1:height(finalDist)
    percentage = (finalDist.GroupCount(i) / height(balancedData)) * 100;
    fprintf('%s: %d samples (%.2f%%)\n', ...
        finalDist.attack_type{i}, finalDist.GroupCount(i), percentage);
end
