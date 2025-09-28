% visualize_feature_distributions.m
% Visualize feature distributions for NORMAL vs SPOOFING in the balanced dataset

data = readtable('training_data/balanced_feature_dataset_20250927_211558.csv');

% Feature columns (adjust if needed)
feature_cols = 7:49; % 43 features
feature_names = data.Properties.VariableNames(feature_cols);

% Example: visualize high-value features (edit as needed)
features_to_plot = [21, 26, 30, 31, 32, 41, 42];

for i = 1:length(features_to_plot)
    fidx = features_to_plot(i);
    figure;
    histogram(data{strcmp(data.attack_type,'NORMAL'), feature_cols(fidx)}, 'FaceAlpha', 0.5, 'EdgeColor', 'none');
    hold on;
    histogram(data{strcmp(data.attack_type,'SPOOFING'), feature_cols(fidx)}, 'FaceAlpha', 0.5, 'EdgeColor', 'none');
    hold off;
    legend('NORMAL', 'SPOOFING');
    title(['Feature: ' feature_names{fidx}]);
    xlabel('Value');
    ylabel('Count');
end
