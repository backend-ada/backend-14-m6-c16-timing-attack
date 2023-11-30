import { hashSeasonPassword, compareHashes } from './password-hasher.js';
import { getUserByName } from './user-model.js';

const login = (username, password) => {
	if (!username || !password) return { error: 'Missing data' };

	const userFound = getUserByName(username);
	if (!userFound) return { message: 'User not found' };

	// Array Destructuring
	const [storedSalt, storedSeasonHash] = userFound.password.split(':');
	const hashedPassword = hashSeasonPassword(password, storedSalt);
	const isLogged = compareHashes(storedSeasonHash, hashedPassword);

	if (!isLogged) return { error: 'Wrong password' };
	return { message: 'User logged successfully!' };
};

export default login;
