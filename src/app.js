import { hash, verify } from 'argon2'
import cors from 'cors'
import 'dotenv/config'
import express from 'express'
import jwt from 'jsonwebtoken'
import { v4 as uuidv4 } from 'uuid'

import prisma from './config/prisma.js'
import generateTokens from './utils/generateTokens.js'

const app = express()
app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(cors({ origin: '*' }))

const PORT = process.env.PORT ?? 8080

app.post('/auth/login', async (req, res) => {
	const data = req.body

	if (!data.email || !data.password) {
		return res
			.status(400)
			.json({ error: 'Email and password are required!' })
	}

	const existingUser = await prisma.user.findUnique({
		where: {
			email: data.email,
		},
	})

	// create new user if not exists
	if (!existingUser) {
		const UUID = uuidv4()
		const hashedPassword = await hash(data.password)

		const newUser = await prisma.user.create({
			data: {
				id: UUID,
				email: data.email,
				password: hashedPassword,
			},
		})

		const tokens = generateTokens({ UUID })

		await prisma.user.update({
			where: { id: newUser.id },
			data: { refreshToken: await hash(tokens.refreshToken) },
		})

		return res.status(200).json({ data: tokens })
	}

	const isPasswordMatched = await verify(existingUser.password, data.password)

	if (!isPasswordMatched) {
		return res.status(400).json({ error: 'Password is incorrect!' })
	}

	const tokens = generateTokens(
		{
			UUID: existingUser.UUID,
		},
		existingUser.UUID,
	)

	await prisma.user.update({
		where: { id: existingUser.id },
		data: { refreshToken: await hash(tokens.refreshToken) },
	})

	res.status(200).json({ data: tokens })
})

app.get('/auth/refresh', async (req, res) => {
	const header = req.headers.authorization
	const [_, token] = header.split(' ') // Bearer [token]

	if (!token) {
		return res.status(400).json({ error: 'Token is required!' })
	}

	try {
		const { UUID } = jwt.verify(token, process.env.JWT_REFRESH_SECRET)

		const existingUser = await prisma.user.findFirst({
			where: { UUID },
		})

		if (!existingUser) {
			return res.status(401).json({ error: 'Refresh token is invalid!' })
		}

		const tokens = generateTokens(
			{
				UUID: existingUser.UUID,
			},
			existingUser.UUID,
		)

		await prisma.user.update({
			where: { id: existingUser.id },
			data: { refreshToken: await hash(tokens.refreshToken) },
		})

		res.status(200).json({ data: tokens })
	} catch (err) {
		return res
			.status(401)
			.json({ error: 'Token is invalid or expired: ' + err.message })
	}
})

// four test accounts, expires in 100 year later
async function main() {
	const testAccount1 = await prisma.user.findFirst({ where: { UUID: '1' } })

	if (!testAccount1) {
		const payloads = [
			{ UUID: '1' },
			{ UUID: '2' },
			{ UUID: '3' },
			{ UUID: '4' },
		]

		payloads.forEach(async (payload) => {
			const hashedPassword = await hash('123456789')

			const newUser = await prisma.user.create({
				data: {
					UUID: payload.UUID,
					email: `test${payload.UUID}@gmail.com`,
					password: hashedPassword,
				},
			})
			const hundredYearLater = '36500d' // 365 * 100 days

			const tokens = {
				accessToken: jwt.sign(payload, process.env.JWT_ACCESS_SECRET, {
					expiresIn: hundredYearLater,
				}),
				refreshToken: jwt.sign(
					payload,
					process.env.JWT_REFRESH_SECRET,
					{
						expiresIn: hundredYearLater,
					},
				),
			}

			await prisma.user.update({
				where: { id: newUser.id },
				data: { refreshToken: await hash(tokens.refreshToken) },
			})
		})
	}
}

main()
	.then(async () => {
		await prisma.$disconnect()
	})
	.catch(async (e) => {
		console.error(e)
		await prisma.$disconnect()
		process.exit(1)
	})

app.listen(PORT, () => {
	console.log(`Master server listening on port ${PORT}`)
})
