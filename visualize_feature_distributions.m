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

% Console summary for each feature
fprintf('\nFeature distribution summary (NORMAL vs SPOOFING):\n');
for i = 1:length(features_to_plot)
    fidx = features_to_plot(i);
    normal_vals = data{strcmp(data.attack_type,'NORMAL'), feature_cols(fidx)};
    spoof_vals = data{strcmp(data.attack_type,'SPOOFING'), feature_cols(fidx)};
    fprintf('\nFeature: %s\n', feature_names{fidx});
    fprintf('  NORMAL:   mean = %.3f, std = %.3f, min = %.3f, max = %.3f\n', mean(normal_vals), std(normal_vals), min(normal_vals), max(normal_vals));
    fprintf('  SPOOFING: mean = %.3f, std = %.3f, min = %.3f, max = %.3f\n', mean(spoof_vals), std(spoof_vals), min(spoof_vals), max(spoof_vals));
    % Optional: print overlap estimate
    overlap = sum(ismember(round(normal_vals,3), round(spoof_vals,3))) / length(normal_vals);
    fprintf('  Overlap (rounded values): %.2f%%\n', 100*overlap);
end
