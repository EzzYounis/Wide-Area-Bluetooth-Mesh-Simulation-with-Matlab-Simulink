function [is_attack, attack_type, confidence] = predictAttackMATLAB(model, features)
% Predict attack using MATLAB Random Forest model
% Inputs:
%   model - TreeBagger model
%   features - 1x43 feature vector
% Outputs:
%   is_attack - boolean, true if attack detected
%   attack_type - string, type of attack or 'NORMAL'
%   confidence - double, prediction confidence [0,1]

try
    % Make prediction
    [prediction, scores] = predict(model, features);
    
    % Extract results
    attack_type = prediction{1};
    confidence = max(scores);
    is_attack = ~strcmp(attack_type, 'NORMAL');
    
    % Ensure confidence is in valid range
    confidence = max(0.1, min(0.99, confidence));
    
catch ME
    % Fallback in case of error
    warning('Prediction failed: %s', ME.message);
    is_attack = false;
    attack_type = 'NORMAL';
    confidence = 0.5;
end
end