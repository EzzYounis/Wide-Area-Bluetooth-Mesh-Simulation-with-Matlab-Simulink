% compare_misclassified_features_all_cleaned.m
% Compare a misclassified sample's features to typical values for both attack types
% using all cleaned balanced feature files in the training_data directory

misclassified_features = [0.1367,0.8750,0.3000,0.9750,0.0544,0.1000,0.6711,0.4847,0.6293,0.1415,0.0571,0.1162,0.0000,0.2000,0.4757,0.9804,0.9069,0.2051,0.1398,0.8545,0.7416,0.5366,0.6960,0.4650,0.8310,0.9747,0.0000,0.0000,0.1075,0.9486,0.9150,0.9022,0.2238,0.0644,0.0000,0.7546,0.9172,0.0000,0.8311,0.7581,0.8014,0.8198,0.0372];

% Get all cleaned balanced feature files
files = dir('training_data/balanced_feature_dataset_*_cleaned.csv');
allT = [];
for k = 1:length(files)
    T = readtable(fullfile(files(k).folder, files(k).name));
    allT = [allT; T];
end

feature_names = allT.Properties.VariableNames(7:end);
features = allT{:,feature_names};
labels = allT.attack_type;

idx_flood = strcmp(labels, 'ADAPTIVE_FLOODING');
idx_spoof = strcmp(labels, 'SPOOFING');

if ~any(idx_spoof)
    warning('No SPOOFING samples in these datasets. Only comparing to ADAPTIVE_FLOODING.');
end

mean_flood = mean(features(idx_flood,:),1);
std_flood = std(features(idx_flood,:),0,1);
if any(idx_spoof)
    mean_spoof = mean(features(idx_spoof,:),1);
    std_spoof = std(features(idx_spoof,:),0,1);
else
    mean_spoof = nan(size(mean_flood));
    std_spoof = nan(size(std_flood));
end

summary = table(feature_names', misclassified_features', mean_flood', std_flood', mean_spoof', std_spoof', ...
    'VariableNames', {'Feature','SampleValue','FloodMean','FloodStd','SpoofMean','SpoofStd'});
disp(summary);

figure;
bar([misclassified_features; mean_flood; mean_spoof]');
legend({'Sample','Flood Mean','Spoof Mean'});
xlabel('Feature Index'); ylabel('Value');
title('Feature Comparison: Misclassified Sample vs. Attack Type Means (All Cleaned Files)');
set(gca,'XTick',1:length(feature_names),'XTickLabel',feature_names,'XTickLabelRotation',45);
grid on;
