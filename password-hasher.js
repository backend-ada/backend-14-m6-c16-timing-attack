import { scryptSync, randomBytes, timingSafeEqual } from 'node:crypto';
import PEPPER from './pepper.js';

// Otra forma de generar SALT es con el método randomBytes
const getSalt = () => randomBytes(15).toString('hex');

const compareHashes = (storedHashedPassword, incomingHash) => {
	const storedHashedPasswordBuffer = Buffer.from(storedHashedPassword, 'hex');

	// En esta caso, para comparar los hashes usamos el método timingSafeEqual de Crypto
	// Básicamente fuerza a que cada ciclo de comparación de caracteres tenga un tiempo equivalente
	// De esta forma, el atacante no puede obtener ninguna información valiosa 
	const match = timingSafeEqual(
		incomingHash,
		storedHashedPasswordBuffer
	);

	return match;
};

// Para el caso de crear el HASH a partir de la sal y la pimienta, usamos scryptSync
// Es un método más seguro que createHASH, ampliamente usado por plataformas de Criptomonedas
const hashSeasonPassword = (password, salt) =>
	scryptSync(password, salt + PEPPER, 45);

export { getSalt, hashSeasonPassword, compareHashes };
