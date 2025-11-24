%% Validate saved RF models in models/ folder
% Scans all bluetooth_mesh_ids_rf_*.mat files and checks whether the
% variable inside is a usable MATLAB classifier (TreeBagger/Ensemble).

clear; clc;
models_dir = 'models';
files = dir(fullfile(models_dir, 'bluetooth_mesh_ids_rf_*.mat'));
if isempty(files)
    fprintf('No model files found in %s\n', models_dir);
    return;
end

fprintf('Found %d model files. Validating...\n\n', numel(files));

for i = 1:numel(files)
    p = fullfile(files(i).folder, files(i).name);
    try
        d = load(p);
        varName = '';
        if isfield(d, 'rf_model')
            varName = 'rf_model';
        elseif isfield(d, 'trainedModel')
            varName = 'trainedModel';
        elseif isfield(d, 'trainedClassifier')
            varName = 'trainedClassifier';
        end
        if isempty(varName)
            fprintf('[%2d] %s -> ❌ no RF variable (rf_model/trainedModel/trainedClassifier)\n', i, files(i).name);
            continue;
        end
        m = d.(varName);
        canPredict = false;
        try
            canPredict = (isobject(m) && ismethod(m, 'predict')) || ...
                        isa(m, 'TreeBagger') || ...
                        isa(m, 'CompactClassificationEnsemble') || ...
                        isa(m, 'ClassificationEnsemble');
        catch
            canPredict = false;
        end
        if canPredict
            classes = {};
            try
                classes = cellstr(m.ClassNames);
            catch
                % ignore
            end
            fprintf('[%2d] %s -> ✅ %s (classes: %s)\n', i, files(i).name, class(m), strjoin(classes, ', '));
        else
            fprintf('[%2d] %s -> ❌ invalid type: %s\n', i, files(i).name, class(m));
        end
    catch ME
        fprintf('[%2d] %s -> ⚠️ load error: %s\n', i, files(i).name, ME.message);
    end
end

fprintf('\nTip: Rebuild with buildRandomForestModel.m if all are invalid.\n');
