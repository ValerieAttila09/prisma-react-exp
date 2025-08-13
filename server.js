import 'dotenv/config'
import express, { json, raw } from 'express'
import { ClerkExpressRequireAuth } from '@clerk/express'
import { clerkClient } from '@clerk/backend'
import cors from 'cors'
import { PrismaClient } from '@prisma/client'

const prisma = new PrismaClient()
const app = express()
const PORT = process.env.PORT || 3000

app.use(json())
app.use(cors())

app.post('/api/webhooks/clerk', raw({ type: "application/json" }), async (req, res) => {
  const WEBHOOK_SECRET = process.env.CLERK_WEBHOOK_SECRET

  if (!WEBHOOK_SECRET) {
    return res.status(400).json({ error: "CLERK_WEBHOOK_SECRET is missing!" })
  }

  try {
    const event = await clerkClient.verifyWebhook({
      payload: req.body,
      secret: WEBHOOK_SECRET,
      header: req.headers['svix-signature']
    })

    if (event.type === 'user.created' || event.type === 'user.updated') {
      const { id, email_addresses, first_name, last_name, primary_email_address_id } = event.data
      const email = email_addresses.find(
        email => email.id === primary_email_address_id
      )?.email_address

      await prisma.user.upsert({
        where: { clerkUserId: id },
        update: {
          email,
          firstName: first_name,
          lastName: last_name
        },
        create: {
          clerkUserId: id,
          email: email || '',
          firstName: first_name,
          lastName: last_name
        }
      })
    }

    return res.status(200).json({ success: true })
  } catch (error) {
    console.error(`error verifying webhook: ${error}`);
    return res.status(400).json({ error: 'webhook verification failed!' })
  }
})

app.get('/api/protected', ClerkExpressRequireAuth(), (req, res) => {
  res.json({ message: 'This is protected data', user: req.auth })
})

app.get('/api/user/:clerkUserId', async (req, res) => {
  try {
    const user = await prisma.user.findUnique({
      where: {
        clerkUserId: req.params.clerkUserId
      }
    })
    res.json(user)
  } catch (error) {
    res.status(500).json({ error: "Internal server error!" })
  }
})

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`)
})