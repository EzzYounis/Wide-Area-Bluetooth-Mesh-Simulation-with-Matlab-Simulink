% merge_and_shuffle_feature_datasets.m
% Merges all feature_dataset CSVs in training_data/ and shuffles the rows, preserving only common headers.

folder = 'training_data';
files = dir(fullfile(folder, '*feature_dataset*_cleaned.csv'));

allTables = {};
commonVars = [];
for k = 1:length(files)
    filePath = fullfile(folder, files(k).name);
    T = readtable(filePath);
    if any(strcmp(T.Properties.VariableNames, 'attack_type'))
        allTables{end+1} = T;
        if isempty(commonVars)
            commonVars = T.Properties.VariableNames;
        else
            commonVars = intersect(commonVars, T.Properties.VariableNames, 'stable');
        end
    else
        fprintf('Skipping %s (no attack_type column)\n', files(k).name);
    end
end

if isempty(allTables)
    error('No tables with attack_type column found.');
end

% Keep only common columns in all tables
for k = 1:length(allTables)
    allTables{k} = allTables{k}(:, commonVars);
end

allData = vertcat(allTables{:});

% Shuffle all rows
rng('shuffle'); % For randomness
shuffledIdx = randperm(height(allData));
allData = allData(shuffledIdx, :);

% Save to a new file with headers
writetable(allData, fullfile(folder, 'merged_shuffled_feature_dataset.csv'));

fprintf('Merged and shuffled %d files. Output: %s\n', length(allTables), fullfile(folder, 'merged_shuffled_feature_dataset.csv'));
