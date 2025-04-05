package clusterpolicyvalidator

// import (
// 	"regexp"
// 	"strconv"

// 	"github.com/go-logr/logr"
// )

// handleConditionValidation handles the validation logic for different operators.
// func handleConditionValidation(operator string, value string, resourceValue []interface{}, logger logr.Logger) bool {
// 	switch operator {
// 	case "In":
// 		logger.Info("Checking if value is in list", "value", value)

//Check if the value is in the list
// 		if !contains(value, resourceValue) {
// 			logger.Error(nil, "Value is not in list", "value", value)
// 			return false
// 		}
// 		logger.Info("Value is in list", "value", value)

//case "NotIn":
//	logger.Info("Checking if value is not in list", "value", value)
//Check if the value is not in the list
//	if contains(value, conditionValue) {
//		logger.Error(nil, "Value is in list", "value", value)
//		return false
//	}
//	logger.Info("Value is not in list", "value", value)

//case "Exists":
//	logger.Info("Checking if key exists in resource", "key", conditionValue)
//Check if the key exists in the resource
//	if !valueExists(value) {
//		logger.Error(nil, "Key does not exist in resource", "key", conditionValue)
//		return false
//	}
//	logger.Info("Key exists in resource", "key", conditionValue)

//case "DoesNotExist":
//	logger.Info("Checking if key does not exist in resource", "key", conditionValue)
//Check if the key does not exist in the resource
//	if valueExists(value) {
//		logger.Error(nil, "Key exists in resource", "key", conditionValue)
//		return false
//	}
//	logger.Info("Key does not exist in resource", "key", conditionValue)

//case "GreaterThan":
//	logger.Info("Checking if value is greater than", "value", value)
//Check if the value is greater than
//	if !greaterThan(value, conditionValue) {
//		logger.Error(nil, "Value is not greater than", "value", value)
//		return false
//	}
//	logger.Info("Value is greater than", "value", value)

//case "LessThan":
//	logger.Info("Checking if value is less than", "value", value)
//Check if the value is less than
//	if !lessThan(value, conditionValue) {
//		logger.Error(nil, "Value is not less than", "value", value)
//		return false
//	}
//	logger.Info("Value is less than", "value", value)

//case "Equal":
//	logger.Info("Checking if value is equal to", "value", value)
//Check if the value is equal to
//	if !equal(value, conditionValue) {
//		logger.Error(nil, "Value is not equal to", "value", value)
//		return false
//	}
//	logger.Info("Value is equal to", "value", value)

//case "NotEqual":
//	logger.Info("Checking if value is not equal to", "value", value)
//Check if the value is not equal to
//	if equal(value, conditionValue) {
//		logger.Error(nil, "Value is equal to", "value", value)
//		return false
//	}
//	logger.Info("Value is not equal to", "value", value)

//case "GreaterThanOrEqual":
//	logger.Info("Checking if value is greater than or equal to", "value", value)
//Check if the value is greater than or equal to
//	if !greaterThanOrEqual(value, conditionValue) {
//		logger.Error(nil, "Value is not greater than or equal to", "value", value)
//		return false
//	}
//	logger.Info("Value is greater than or equal to", "value", value)

//case "LessThanOrEqual":
//	logger.Info("Checking if value is less than or equal to", "value", value)
//Check if the value is less than or equal to
//	if !lessThanOrEqual(value, conditionValue) {
//		logger.Error(nil, "Value is not less than or equal to", "value", value)
//		return false
//	}
//	logger.Info("Value is less than or equal to", "value", value)

//case "DoesNotMatch":
//	logger.Info("Checking if value does not match", "value", value)
//Check if the value does not match
//	if !doesNotMatch(value, conditionValue) {
//		logger.Error(nil, "Value does match", "value", value)
//		return false
//	}
//	logger.Info("Value does not match", "value", value)

//case "Matches":
//	logger.Info("Checking if value matches", "value", value)
//Check if the value matches
//	if !matches(value, conditionValue) {
//		logger.Error(nil, "Value does not match", "value", value)
//		return false
//	}
//	logger.Info("Value matches", "value", value)

// 	default:
// 		logger.Error(nil, "Unsupported operator", "operator", operator)
// 		return false
// 	}
// 	return true
// }

// matches verifica si un valor de tipo cadena coincide con un patrón de expresión regular.
// func matches(value string, pattern string) bool {
// 	matched, err := regexp.MatchString(pattern, value)
// 	return err == nil && matched
// }

// doesNotMatch verifica si un valor de tipo cadena **no** coincide con un patrón de expresión regular.
// func doesNotMatch(value string, pattern string) bool {
// 	matched, err := regexp.MatchString(pattern, value)
// 	return err == nil && !matched
// }

// lessThanOrEqual verifica si el valor de `value` es menor o igual que `comparisonValue`.
// Asume que ambos son números.
// func lessThanOrEqual(value string, comparisonValue string) bool {
// 	val, err := strconv.ParseFloat(value, 64)
// 	if err != nil {
// 		return false
// 	}

// 	compVal, err := strconv.ParseFloat(comparisonValue, 64)
// 	if err != nil {
// 		return false
// 	}

// 	return val <= compVal
// }

// greaterThanOrEqual verifica si el valor de `value` es mayor o igual que `comparisonValue`.
// Asume que ambos son números.
// func greaterThanOrEqual(value string, comparisonValue string) bool {
// 	val, err := strconv.ParseFloat(value, 64)
// 	if err != nil {
// 		return false
// 	}

// 	compVal, err := strconv.ParseFloat(comparisonValue, 64)
// 	if err != nil {
// 		return false
// 	}

// 	return val >= compVal
// }

// contains verifica si un valor está en una lista de valores
// func contains(value string, resourceValue []interface{}) bool {

// 	for _, v := range resourceValue {
// 		if v == value {
// 			return true
// 		}
// 	}
// 	return false
// }

// equal verifica si dos valores son iguales
// func equal(value1 string, value2 string) bool {
// 	return value1 == value2
// }

// greaterThan verifica si value1 es mayor que value2
// func greaterThan(value1 string, value2 string) bool {
// 	val1, err := strconv.ParseFloat(value1, 64)
// 	if err != nil {
// 		return false
// 	}

// 	val2, err := strconv.ParseFloat(value2, 64)
// 	if err != nil {
// 		return false
// 	}

// 	return val1 > val2
// }

// lessThan verifica si value1 es menor que value2
// func lessThan(value1 string, value2 string) bool {
// 	val1, err := strconv.ParseFloat(value1, 64)
// 	if err != nil {
// 		return false
// 	}

// 	val2, err := strconv.ParseFloat(value2, 64)
// 	if err != nil {
// 		return false
// 	}

// 	return val1 < val2
// }
//
