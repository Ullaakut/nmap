package slices

// Adapted from
// https://siongui.github.io/2018/04/14/go-remove-duplicates-from-slice-or-array/
// RemoveDuplicatesFromStringSlice
func RemoveDuplicatesFromStringSlice(s []string) []string {
	m := make(map[string]struct{})
	var result []string
	for _, item := range s {
		if _, ok := m[item]; !ok {
			m[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}
