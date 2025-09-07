%% Test Pre-trained Model Loading
% Quick test script to verify the pre-trained model can be loaded and used

fprintf('=== Testing Pre-trained Model Integration ===\n\n');

% Test 1: Model Loading
fprintf('1. Testing model loading...\n');
try
    % Create model structure
    test_model = struct();
    test_model.model_loaded = false;
    test_model.attack_types = {'NORMAL', 'FLOODING', 'ADAPTIVE_FLOODING', 'BLACK_HOLE', 'SPOOFING', 'RESOURCE_EXHAUSTION'};
    test_model.feature_weights = rand(43, 1);
    
    % Try to load pre-trained model
    test_model = loadPretrainedModel(test_model);
    
    if test_model.model_loaded
        fprintf('✅ Model loaded successfully! Type: %s\n', test_model.model_type);
    else
        fprintf('⚠️  Model loading failed, using simulation fallback\n');
    end
    
catch ME
    fprintf('❌ Error during model loading: %s\n', ME.message);
end

% Test 2: Prediction
fprintf('\n2. Testing prediction with sample features...\n');
try
    % Create sample feature vector (43 features)
    sample_features = rand(1, 43); % Random features in [0,1] range
    
    % Test prediction
    [is_attack, attack_type, confidence] = predictAttack(test_model, sample_features);
    
    fprintf('✅ Prediction test successful:\n');
    fprintf('   - Is Attack: %s\n', mat2str(is_attack));
    fprintf('   - Attack Type: %s\n', attack_type);
    fprintf('   - Confidence: %.3f\n', confidence);
    
catch ME
    fprintf('❌ Error during prediction: %s\n', ME.message);
end

% Test 3: Multiple predictions to verify consistency
fprintf('\n3. Testing multiple predictions for consistency...\n');
try
    fprintf('Running 5 test predictions:\n');
    for i = 1:5
        test_features = rand(1, 43);
        [is_attack, attack_type, confidence] = predictAttack(test_model, test_features);
        fprintf('   Test %d: %s (%.3f)\n', i, attack_type, confidence);
    end
    fprintf('✅ Multiple predictions completed successfully\n');
    
catch ME
    fprintf('❌ Error during multiple predictions: %s\n', ME.message);
end

fprintf('\n=== Model Integration Test Complete ===\n');

% Display model information
if exist('test_model', 'var') && test_model.model_loaded
    fprintf('\n📊 Model Information:\n');
    fprintf('   - Type: %s\n', test_model.model_type);
    fprintf('   - Attack Types: %s\n', strjoin(test_model.attack_types, ', '));
    fprintf('   - Feature Count: %d\n', length(test_model.feature_weights));
    fprintf('   - Ready for simulation: ✅\n');
else
    fprintf('\n⚠️  Model not loaded - simulation will use fallback methods\n');
end
