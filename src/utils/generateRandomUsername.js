import {
	adjectives,
	animals,
	uniqueNamesGenerator,
} from 'unique-names-generator'

const generateRandomUsername = () => {
	return uniqueNamesGenerator({
		dictionaries: [adjectives, animals], // Use built-in dictionaries
		separator: '',
		length: 2,
		style: 'capital',
	})
}

export default generateRandomUsername
