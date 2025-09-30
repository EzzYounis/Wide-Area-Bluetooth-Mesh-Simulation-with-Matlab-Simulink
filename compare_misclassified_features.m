% compare_misclassified_features.m
% Compare a misclassified sample's features to typical values for both attack types

% User: Update these values with the misclassified sample's features
misclassified_features = [0.1367,0.8750,0.3000,0.9750,0.0544,0.1000,0.6711,0.4847,0.6293,0.1415,0.0571,0.1162,0.0000,0.2000,0.4757,0.9804,0.9069,0.2051,0.1398,0.8545,0.7416,0.5366,0.6960,0.4650,0.8310,0.9747,0.0000,0.0000,0.1075,0.9486,0.9150,0.9022,0.2238,0.0644,0.0000,0.7546,0.9172,0.0000,0.8311,0.7581,0.8014,0.8198,0.0372];

% Load the latest balanced feature dataset
T = readtable('training_data/balanced_feature_dataset_20250928_135236.csv');

% Only keep relevant features and attack_type
feature_names = T.Properties.VariableNames(7:end);
features = T{:,feature_names};
labels = T.attack_type;

% Find all ADAPTIVE_FLOODING and SPOOFING samples
idx_flood = strcmp(labels, 'ADAPTIVE_FLOODING');
idx_spoof = strcmp(labels, 'SPOOFING');

% If no SPOOFING samples, warn and skip
if ~any(idx_spoof)
    warning('No SPOOFING samples in this dataset. Only comparing to ADAPTIVE_FLOODING.');
end

% Compute mean and std for each feature
mean_flood = mean(features(idx_flood,:),1);
std_flood = std(features(idx_flood,:),0,1);
if any(idx_spoof)
    mean_spoof = mean(features(idx_spoof,:),1);
    std_spoof = std(features(idx_spoof,:),0,1);
else
    mean_spoof = nan(size(mean_flood));
    std_spoof = nan(size(std_flood));
end

% Create summary table
summary = table(feature_names', misclassified_features', mean_flood', std_flood', mean_spoof', std_spoof', ...
    'VariableNames', {'Feature','SampleValue','FloodMean','FloodStd','SpoofMean','SpoofStd'});
disp(summary);

% Optional: visualize as bar plot
figure;
bar([misclassified_features; mean_flood; mean_spoof]');
legend({'Sample','Flood Mean','Spoof Mean'});
xlabel('Feature Index'); ylabel('Value');
title('Feature Comparison: Misclassified Sample vs. Attack Type Means');
set(gca,'XTick',1:length(feature_names),'XTickLabel',feature_names,'XTickLabelRotation',45);
grid on;
