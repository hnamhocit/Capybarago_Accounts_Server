import jwt from 'jsonwebtoken'

const generateTokens = (payload) => {
	const isTestUUID = payload.UUID
		? payload.UUID in ['1', '2', '3', '4']
		: false
	const hundredYearLater = '36500d' // 365 * 100 days

	return {
		accessToken: jwt.sign(payload, process.env.JWT_ACCESS_SECRET, {
			expiresIn: isTestUUID
				? hundredYearLater
				: process.env.JWT_ACCESS_EXPIRESIN,
		}),
		refreshToken: jwt.sign(payload, process.env.JWT_REFRESH_SECRET, {
			expiresIn: isTestUUID
				? hundredYearLater
				: process.env.JWT_REFRESH_EXPIRESIN,
		}),
	}
}

export default generateTokens
