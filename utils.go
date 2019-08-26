package nmap

// https://siongui.github.io/2018/04/14/go-remove-duplicates-from-slice-or-array/
func RemoveDuplicatesFromSlice(s []string) []string {
	m := make(map[string]struct{})
	for _, item := range s {
		if _, ok := m[item]; ok {
		} else {
			m[item] = true
		}
	}

	var result []string
	for item := range m {
		result = append(result, item)
	}
	return result
}
