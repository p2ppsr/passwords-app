/* eslint-disable @typescript-eslint/no-non-null-assertion */
/**
 * Passkey Vault (BSV / PushDrop / BRC100)
 *
 * Core ideas:
 * - Each password entry is a PushDrop output locked to the current user
 * - The payload stores an encrypted JSON blob for: { title, username, password, totpSecret? }
 * - Entries live in the 'password entries' basket
 * - Create/Edit/Delete are on-chain actions (similar to your ToDo example)
 * - TOTP codes (RFC6238) via otplib; QR scanning of otpauth:// URIs via react-qr-reader
 *
 * Protocol IDs used: [0, 'password manager'] with keyID '1'
 */

import React, { useCallback, useEffect, useMemo, useState, type FormEvent } from 'react'

import {
  AppBar, Toolbar, Typography, IconButton, Grid, Button, Fab, LinearProgress, TextField,
  Dialog, DialogTitle, DialogContent, DialogActions, DialogContentText, List, ListItem,
  InputAdornment, useMediaQuery, Menu, MenuItem,
  Chip, Box, Tooltip, Snackbar, Alert, Paper, Stack, type AlertColor
} from '@mui/material'
import { styled } from '@mui/system'
import { alpha } from '@mui/material/styles'
import AddIcon from '@mui/icons-material/Add'
import GitHubIcon from '@mui/icons-material/GitHub'
import VisibilityIcon from '@mui/icons-material/Visibility'
import VisibilityOffIcon from '@mui/icons-material/VisibilityOff'
import ContentCopyIcon from '@mui/icons-material/ContentCopy'
import EditIcon from '@mui/icons-material/Edit'
import DeleteIcon from '@mui/icons-material/Delete'
import QrCodeScannerIcon from '@mui/icons-material/QrCodeScanner'
import MoreVertIcon from '@mui/icons-material/MoreVert'
import SearchIcon from '@mui/icons-material/Search'

import useAsyncEffect from 'use-async-effect'
import { NoMncModal, checkForMetaNetClient } from 'metanet-react-prompt'
import {
  WalletClient, PushDrop, Utils, Transaction, LockingScript,
  type WalletOutput, type WalletProtocol,
  Random
} from '@bsv/sdk'
import BabbageGo from '@babbage/go'

import { QrReader } from 'react-qr-reader'

import './App.scss'

// ------------- Constants / Protocol -------------

const PROTOCOL_ID: WalletProtocol = [2, 'password manager']
const DEFAULT_CREATE_AMOUNT = 1 // sat
const PASSWORD_BASKET = 'password entries'

// ------------- Styling -------------

const AppBarPlaceholder = styled('div')(({ theme }) => ({
  ...theme.mixins.toolbar,
  marginBottom: theme.spacing(3)
}))
const Shell = styled('div')(({ theme }) => ({
  maxWidth: '1120px',
  margin: '0 auto',
  width: '100%',
  padding: theme.spacing(5, 4, 10),
  [theme.breakpoints.down('md')]: {
    padding: theme.spacing(4, 3, 8)
  },
  [theme.breakpoints.down('sm')]: {
    padding: theme.spacing(3, 2, 7)
  }
}))
const AddMoreFab = styled(Fab)(({ theme }) => ({
  position: 'fixed',
  right: theme.spacing(2),
  bottom: theme.spacing(2.5),
  zIndex: 10,
  boxShadow: '0 18px 40px rgba(80, 231, 163, 0.35)'
}))
const LoadingBar = styled(LinearProgress)(({ theme }) => ({
  margin: theme.spacing(1.5, 0)
}))
const GitHubIconStyle = styled(IconButton)(({ theme }) => ({
  color: theme.palette.text.primary,
  backgroundColor: alpha(theme.palette.common.white, 0.08),
  borderRadius: theme.shape.borderRadius,
  '&:hover': {
    backgroundColor: alpha(theme.palette.common.white, 0.16)
  }
}))
const HeroCard = styled(Paper)(({ theme }) => ({
  padding: theme.spacing(4),
  borderRadius: theme.shape.borderRadius * 1.25,
  background: 'linear-gradient(135deg, rgba(80, 231, 163, 0.12) 0%, rgba(59, 130, 246, 0.08) 100%)',
  border: `1px solid ${alpha(theme.palette.primary.light, 0.35)}`,
  boxShadow: '0 32px 120px rgba(15, 34, 60, 0.45)',
  backdropFilter: 'blur(20px)',
  display: 'flex',
  flexDirection: 'column',
  gap: theme.spacing(2.5),
  [theme.breakpoints.down('sm')]: {
    padding: theme.spacing(3)
  }
}))
const SearchSurface = styled(Paper)(({ theme }) => ({
  padding: theme.spacing(3),
  borderRadius: theme.shape.borderRadius * 1.1,
  backgroundColor: alpha(theme.palette.background.paper, 0.85),
  border: `1px solid ${alpha(theme.palette.primary.light, 0.2)}`,
  display: 'grid',
  gap: theme.spacing(2),
  [theme.breakpoints.down('sm')]: {
    padding: theme.spacing(2.5)
  }
}))
const NoItems = styled(Grid)(({ theme }) => ({
  margin: 'auto',
  textAlign: 'center',
  marginTop: theme.spacing(8),
  gap: theme.spacing(3)
}))
const PasswordCard = styled(Box)(({ theme }) => ({
  display: 'flex',
  flexDirection: 'column',
  gap: theme.spacing(2),
  width: '100%',
  borderRadius: theme.shape.borderRadius * 1.15,
  border: `1px solid ${alpha(theme.palette.primary.main, 0.25)}`,
  padding: theme.spacing(2.5),
  background: 'linear-gradient(145deg, rgba(9, 20, 42, 0.9) 0%, rgba(9, 30, 60, 0.65) 100%)',
  boxShadow: '0 18px 60px rgba(7, 22, 48, 0.35)',
  backdropFilter: 'blur(14px)',
  transition: 'box-shadow 160ms ease, transform 160ms ease',
  '&:hover': {
    boxShadow: '0 32px 80px rgba(7, 26, 58, 0.45)',
    transform: 'translateY(-3px)'
  }
}))
const PasswordValue = styled('span')(({ theme }) => ({
  fontFamily: 'monospace',
  letterSpacing: '0.08em',
  padding: theme.spacing(0.5, 1),
  borderRadius: theme.shape.borderRadius,
  backgroundColor: alpha(theme.palette.secondary.main, 0.12),
  border: `1px dashed ${alpha(theme.palette.secondary.main, 0.45)}`
}))

// ------------- Types -------------

type PasswordPayload = {
  title: string
  username: string
  password: string
  totpSecret?: string // base32
  issuer?: string
  accountName?: string
  createdAt: string // ISO
  updatedAt?: string // ISO
}

export type PasswordEntry = {
  sats: number
  outpoint: string
  keyID: string
  lockingScript: string
  beef: number[] | undefined
  payload: PasswordPayload
}

// ------------- Wallet -------------

const walletClient = new BabbageGo(new WalletClient(), {
  walletUnavailable: {
    title: 'Connect the MetaNet Client',
    message: 'Passkey Vault relies on the MetaNet Client to encrypt and anchor your credentials. Install it to continue.',
    ctaText: 'Install MetaNet Client',
    ctaHref: 'https://metanet.id/download'
  },
  funding: {
    title: 'Top Up Your Vault',
    introText: 'Every encrypted entry needs a sprinkle of sats to live forever on-chain. Add a little balance to keep saving passwords.',
    postPurchaseText: 'Great! Funds landed safely — you are ready to store secrets.',
    buySatsText: 'Buy sats',
    retryText: 'Check balance again',
    cancelText: 'Go back',
    buySatsUrl: 'https://handcash.io/buy-bitcoin'
  },
  monetization: {
    developerIdentity: '02a064784ebb435e87c3961745b01e3564d41149ea1291d1a73783d1b7b3a7a220',
    developerFeeSats: 200
  },
  design: {
    preset: 'emberLagoon',
    tokens: {
      overlayColor: 'rgba(7, 15, 26, 0.82)',
      cardBackground: 'rgba(15, 23, 42, 0.94)',
      cardBorder: 'rgba(148, 163, 184, 0.25)',
      cardShadow: '0 24px 60px rgba(8, 24, 64, 0.35)',
      cardRadius: '18px',
      fontFamily: '\'Inter\', \'Roboto\', sans-serif',
      textPrimary: '#e2e8f0',
      textMuted: 'rgba(148, 163, 184, 0.86)',
      accentBackground: '#50e7a3',
      accentText: '#041b24',
      accentHoverBackground: '#6bf1b6',
      accentHoverText: '#01120f',
      accentBorder: 'rgba(80, 231, 163, 0.5)',
      secondaryBackground: 'rgba(37, 51, 79, 0.75)',
      secondaryText: '#e0f2fe',
      secondaryHoverBackground: 'rgba(59, 77, 112, 0.8)',
      secondaryBorder: 'rgba(94, 234, 212, 0.35)',
      focusRing: '0 0 0 3px rgba(94, 234, 212, 0.45)',
      focusGlow: '0 0 0 6px rgba(94, 234, 212, 0.2)',
      smallLabelColor: 'rgba(148, 163, 184, 0.7)',
      buttonShadow: '0 18px 40px rgba(80, 231, 163, 0.35)',
      buttonShape: 'soft'
    }
  }
})

// ------------- Helpers -------------

function mask(val: string): string {
  if (!val) return ''
  return '•'.repeat(val.length)
}

function formatTimestamp(iso?: string): string {
  if (!iso) return ''
  const parsed = new Date(iso)
  if (Number.isNaN(parsed.getTime())) return ''
  return parsed.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

function isValidBase32(s: string): boolean {
  // Basic sanity; otplib will further validate at use
  return /^[A-Z2-7]+=*$/i.test(s.replace(/\s+/g, ''))
}

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

function base32ToBytes(secret: string): Uint8Array {
  const clean = secret.replace(/\s+/g, '').toUpperCase().replace(/=+$/, '')
  let bits = 0
  let value = 0
  const output: number[] = []

  for (const char of clean) {
    const idx = BASE32_ALPHABET.indexOf(char)
    if (idx === -1) throw new Error('Invalid base32 character')
    value = (value << 5) | idx
    bits += 5
    if (bits >= 8) {
      bits -= 8
      output.push((value >> bits) & 0xff)
    }
  }

  return new Uint8Array(output)
}

function getWebCrypto(): SubtleCrypto | null {
  if (typeof globalThis === 'undefined') return null
  const cryptoObj = (globalThis as unknown as { crypto?: Crypto }).crypto
  return cryptoObj?.subtle ?? null
}

async function generateTotp(secret: string, counter: number, digits = 6, subtle?: SubtleCrypto): Promise<string> {
  const subtleCrypto = subtle ?? getWebCrypto()
  if (!subtleCrypto) throw new Error('WebCrypto SubtleCrypto is unavailable')

  const normalizedSecret = secret.replace(/\s+/g, '').toUpperCase()
  const keyBytes = base32ToBytes(normalizedSecret)
  if (keyBytes.length === 0) throw new Error('Decoded TOTP secret is empty')

  const algorithm: HmacImportParams = { name: 'HMAC', hash: 'SHA-1' }
  const cryptoKey = await subtleCrypto.importKey('raw', keyBytes, algorithm, false, ['sign'])

  const buffer = new ArrayBuffer(8)
  const view = new DataView(buffer)
  const high = Math.floor(counter / 0x100000000)
  const low = counter >>> 0
  view.setUint32(0, high, false)
  view.setUint32(4, low, false)

  const signature = new Uint8Array(await subtleCrypto.sign(algorithm, cryptoKey, buffer))
  const offset = signature[signature.length - 1] & 0x0f
  const binary =
    ((signature[offset] & 0x7f) << 24) |
    ((signature[offset + 1] & 0xff) << 16) |
    ((signature[offset + 2] & 0xff) << 8) |
    (signature[offset + 3] & 0xff)

  return (binary % 10 ** digits).toString().padStart(digits, '0')
}

function parseOtpauth(uri: string): Partial<PasswordPayload> | null {
  try {
    const url = new URL(uri)
    if (url.protocol !== 'otpauth:') return null
    const type = url.host // 'totp'
    if (type !== 'totp') return null
    // Pathname like: /Issuer:Account or /Account
    const label = decodeURIComponent(url.pathname.replace(/^\//, ''))
    let issuerFromLabel: string | undefined
    let accountName: string | undefined
    if (label.includes(':')) {
      const [iss, acct] = label.split(':')
      issuerFromLabel = iss
      accountName = acct
    } else {
      accountName = label
    }
    const secret = url.searchParams.get('secret') || undefined
    const issuer = url.searchParams.get('issuer') || issuerFromLabel
    if (!secret) return null
    return {
      totpSecret: secret.replace(/\s+/g, ''),
      issuer,
      accountName
    }
  } catch {
    return null
  }
}

// ------------- Main Component -------------

const App: React.FC = () => {
  // MNC presence
  const [isMncMissing, setIsMncMissing] = useState<boolean>(false)

  // Loading flags
  const [loadingList, setLoadingList] = useState<boolean>(true)
  const [creating, setCreating] = useState<boolean>(false)
  const [deleting, setDeleting] = useState<boolean>(false)
  const [editing, setEditing] = useState<boolean>(false)

  // Data
  const [entries, setEntries] = useState<PasswordEntry[]>([])
  const [filter, setFilter] = useState<string>('')

  // Dialog states
  const [createOpen, setCreateOpen] = useState<boolean>(false)
  const [editOpen, setEditOpen] = useState<boolean>(false)
  const [qrOpen, setQrOpen] = useState<boolean>(false)
  const [confirmDeleteOpen, setConfirmDeleteOpen] = useState<boolean>(false)

  // Selection / menu
  const [selected, setSelected] = useState<PasswordEntry | null>(null)
  const [menuAnchor, setMenuAnchor] = useState<HTMLElement | null>(null)

  // New/Edit form state
  const [formTitle, setFormTitle] = useState<string>('')
  const [formUsername, setFormUsername] = useState<string>('')
  const [formPassword, setFormPassword] = useState<string>('')
  const [formTotp, setFormTotp] = useState<string>('') // base32

  // UI toggles
  const [vaultVisible, setVaultVisible] = useState<boolean>(false)
  const [revealedEntries, setRevealedEntries] = useState<Record<string, boolean>>({})
  const [formPasswordVisible, setFormPasswordVisible] = useState<boolean>(false)
  const [toast, setToast] = useState<{ message: string, severity: AlertColor } | null>(null)

  // Responsive layout
  const small = useMediaQuery('(max-width:600px)')

  const showToast = useCallback((message: string, severity: AlertColor = 'info') => {
    setToast({ message, severity })
  }, [])

  const handleToastClose = useCallback((_: React.SyntheticEvent | Event, reason?: string) => {
    if (reason === 'clickaway') return
    setToast(null)
  }, [])

  const handleCopy = useCallback((text: string, successMessage: string) => {
    navigator.clipboard.writeText(text).then(() => {
      showToast(successMessage, 'success')
    }).catch(() => {
      showToast('Failed to copy to clipboard', 'error')
    })
  }, [showToast])

  const toggleVaultVisibility = useCallback(() => {
    setVaultVisible(prev => {
      const next = !prev
      if (!next) setRevealedEntries({})
      return next
    })
  }, [setRevealedEntries])

  const showVault = useCallback(() => {
    setVaultVisible(true)
  }, [])

  const toggleEntryVisibility = useCallback((id: string) => {
    if (!vaultVisible) return
    setRevealedEntries(prev => {
      const next = { ...prev }
      if (next[id]) delete next[id]
      else next[id] = true
      return next
    })
  }, [vaultVisible])

  // TOTP live code handling
  const [tick, setTick] = useState<number>(0) // force re-render each second
  const [totpCodes, setTotpCodes] = useState<Record<string, { code: string, remaining: number }>>({})
  useEffect(() => {
    const i = setInterval(() => setTick(t => t + 1), 1000)
    return () => clearInterval(i)
  }, [])
  const fallbackRemaining = useMemo(() => {
    const step = 30
    const epochSeconds = Math.floor(Date.now() / 1000)
    const remainder = epochSeconds % step
    return remainder === 0 ? step : step - remainder
  }, [tick])
  useEffect(() => {
    let cancelled = false
    const step = 30
    const updateTotpCodes = async () => {
      const subtle = getWebCrypto()
      const entriesWithTotp = entries.filter(entry => {
        const secret = entry.payload.totpSecret
        return Boolean(secret && isValidBase32(secret))
      })

      if (!subtle || entriesWithTotp.length === 0) {
        setTotpCodes(prev => (Object.keys(prev).length ? {} : prev))
        return
      }

      const epochSeconds = Math.floor(Date.now() / 1000)
      const remainder = epochSeconds % step
      const remaining = remainder === 0 ? step : step - remainder
      const counter = Math.floor(epochSeconds / step)

      const updates = await Promise.all(entriesWithTotp.map(async entry => {
        try {
          const code = await generateTotp(entry.payload.totpSecret!, counter, 6, subtle)
          return [entry.outpoint, { code, remaining }] as const
        } catch (err) {
          console.error('Failed to generate TOTP code:', err)
          return [entry.outpoint, { code: '', remaining: 0 }] as const
        }
      }))

      if (!cancelled) {
        const next = Object.fromEntries(updates) as Record<string, { code: string, remaining: number }>
        setTotpCodes(next)
      }
    }

    void updateTotpCodes()

    return () => { cancelled = true }
  }, [entries, tick])

  // Poll for MetaNet Client (same as your ToDo app)
  useAsyncEffect(() => {
    const id = setInterval(() => {
      checkForMetaNetClient().then(hasMNC => {
        if (hasMNC === 0) setIsMncMissing(true)
        else {
          setIsMncMissing(false)
          clearInterval(id)
        }
      }).catch(err => console.error('Error checking MetaNet Client:', err))
    }, 1000)
    return () => clearInterval(id)
  }, [])

  // ----- List / Load -----

  const loadEntries = async () => {
    try {
      setLoadingList(true)
      const res = await walletClient.listOutputs({
        basket: PASSWORD_BASKET,
        include: 'entire transactions',
        includeCustomInstructions: true,
        limit: 1000
      })

      const results = await Promise.all(
        res.outputs.map(async (wo: WalletOutput) => {
          try {
            const txid = wo.outpoint.split('.')[0]
            const tx = Transaction.fromBEEF(res.BEEF as number[], txid)
            const lockingScript = tx!.outputs[0].lockingScript
            const decoded = PushDrop.decode(lockingScript)
            const { keyID } = JSON.parse(wo.customInstructions as string)
            const encryptedBlob = decoded.fields[0]
            const dec = await walletClient.decrypt({
              ciphertext: encryptedBlob,
              protocolID: PROTOCOL_ID,
              keyID
            })
            const payload: PasswordPayload = JSON.parse(Utils.toUTF8(dec.plaintext))

            const entry: PasswordEntry = {
              sats: wo.satoshis ?? 0,
              outpoint: `${txid}.0`,
              lockingScript: lockingScript.toHex(),
              beef: res.BEEF,
              keyID,
              payload
            }
            return entry
          } catch (err) {
            console.error('Error decrypting an entry:', err)
            return null
          }
        })
      )

      const filtered = (results.filter(Boolean) as PasswordEntry[]).reverse()
      setEntries(filtered)
      setRevealedEntries(prev => {
        if (!Object.keys(prev).length) return prev
        const valid = new Set(filtered.map(f => f.outpoint))
        let mutated = false
        const next: Record<string, boolean> = {}
        for (const key of Object.keys(prev)) {
          if (valid.has(key)) {
            next[key] = true
          } else {
            mutated = true
          }
        }
        return mutated ? next : prev
      })
    } catch (e: any) {
      const code = e?.code
      if (code !== 'ERR_NO_METANET_IDENTITY') {
        showToast(`Failed to load password entries: ${e.message}`, 'error')
        console.error(e)
      }
    } finally {
      setLoadingList(false)
    }
  }

  useEffect(() => { void loadEntries() }, [])

  // ----- Filtered list -----

  const visible = useMemo(() => {
    const q = filter.trim().toLowerCase()
    if (!q) return entries
    return entries.filter(e => {
      const { title, username, issuer, accountName } = e.payload
      return [title, username, issuer, accountName].some(v => v?.toLowerCase().includes(q))
    })
  }, [entries, filter])

  // ----- Create -----

  const openCreate = () => {
    setFormTitle('')
    setFormUsername('')
    setFormPassword('')
    setFormTotp('')
    setFormPasswordVisible(false)
    setCreateOpen(true)
  }

  const handleCreate = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    try {
      if (!formTitle.trim()) {
        showToast('Enter a title (site / label)', 'warning')
        return
      }
      if (!formUsername.trim()) {
        showToast('Enter a username', 'warning')
        return
      }
      if (!formPassword) {
        showToast('Enter a password', 'warning')
        return
      }

      if (formTotp && !isValidBase32(formTotp)) {
        showToast('TOTP secret must be base32', 'warning')
        return
      }

      setCreating(true)

      const now = new Date().toISOString()
      const payload: PasswordPayload = {
        title: formTitle.trim(),
        username: formUsername.trim(),
        password: formPassword,
        totpSecret: formTotp.trim() || undefined,
        createdAt: now
      }

      // Prepare PushDrop script
      const pushdrop = new PushDrop(walletClient)
      const keyID = Utils.toBase64(Random(16))
      const fields = await (async () => {
        const encrypted = (await walletClient.encrypt({
          plaintext: Utils.toArray(JSON.stringify(payload), 'utf8'),
          protocolID: PROTOCOL_ID,
          keyID
        })).ciphertext
        return [
          encrypted
        ]
      })()

      const lockingScript = await pushdrop.lock(fields, PROTOCOL_ID, keyID, 'self')

      const action = await walletClient.createAction({
        outputs: [{
          lockingScript: lockingScript.toHex(),
          satoshis: DEFAULT_CREATE_AMOUNT,
          basket: PASSWORD_BASKET,
          outputDescription: `Password entry: ${payload.title}`,
          customInstructions: JSON.stringify({ keyID })
        }],
        options: { randomizeOutputs: false, acceptDelayedBroadcast: true },
        description: `Create a password entry for ${payload.title}`
      })

      const newEntry: PasswordEntry = {
        sats: DEFAULT_CREATE_AMOUNT,
        outpoint: `${action.txid}.0`,
        lockingScript: lockingScript.toHex(),
        beef: action.tx,
        keyID,
        payload
      }

      setEntries(prev => [newEntry, ...prev])
      setCreateOpen(false)
      showToast('Password saved', 'success')
    } catch (e: any) {
      showToast(e.message || 'Failed to create password entry', 'error')
      console.error(e)
    } finally {
      setCreating(false)
    }
  }

  // ----- Delete (spend old output back to wallet) -----

  const requestDelete = (entry: PasswordEntry) => {
    setSelected(entry)
    setConfirmDeleteOpen(true)
  }

  const handleDelete = async () => {
    if (!selected) return
    try {
      setDeleting(true)
      const { beef, sats,keyID } = selected

      const { signableTransaction } = await walletClient.createAction({
        description: `Delete password: ${selected.payload.title}`,
        inputBEEF: beef,
        inputs: [{
          inputDescription: 'Delete password entry',
          outpoint: selected.outpoint,
          unlockingScriptLength: 73
        }],
        options: { acceptDelayedBroadcast: true, randomizeOutputs: false }
      })

      if (!signableTransaction) throw new Error('Failed to create signable transaction')
      const partialTx = Transaction.fromBEEF(signableTransaction.tx)
      const unlocker = new PushDrop(walletClient).unlock(
        PROTOCOL_ID, keyID, 'self', 'all', false, sats, LockingScript.fromHex(selected.lockingScript)
      )
      const unlockingScript = await unlocker.sign(partialTx, 0)

      await walletClient.signAction({
        reference: signableTransaction.reference,
        spends: { 0: { unlockingScript: unlockingScript.toHex() } }
      })

      setEntries(prev => prev.filter(e => e !== selected))
      setRevealedEntries(prev => {
        if (!prev[selected.outpoint]) return prev
        const next = { ...prev }
        delete next[selected.outpoint]
        return next
      })
      setSelected(null)
      setConfirmDeleteOpen(false)
      showToast('Password deleted', 'success')
    } catch (e: any) {
      showToast(e.message || 'Failed to delete password', 'error')
      console.error(e)
    } finally {
      setDeleting(false)
    }
  }

  // ----- Edit (delete old, then create new) -----
  // We do a reliable 2-step: spend old output (like delete), then create fresh output with updated payload.
  // This avoids assumptions about mixing custom outputs with spends in a single action flow.

  const openEdit = (entry: PasswordEntry) => {
    setSelected(entry)
    setFormTitle(entry.payload.title)
    setFormUsername(entry.payload.username)
    setFormPassword(entry.payload.password)
    setFormTotp(entry.payload.totpSecret || '')
    setFormPasswordVisible(false)
    setEditOpen(true)
  }

  const handleEdit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    if (!selected) return
    try {
      if (!formTitle.trim()) {
        showToast('Enter a title (site / label)', 'warning')
        return
      }
      if (!formUsername.trim()) {
        showToast('Enter a username', 'warning')
        return
      }
      if (!formPassword) {
        showToast('Enter a password', 'warning')
        return
      }
      if (formTotp && !isValidBase32(formTotp)) {
        showToast('TOTP secret must be base32', 'warning')
        return
      }

      setEditing(true)
      const satoshiAmount = selected.sats ?? DEFAULT_CREATE_AMOUNT

      // First create new to ensure data will persist before deleting old
      {
        const keyID = Utils.toBase64(Random(16))
        const now = new Date().toISOString()
        const payload: PasswordPayload = {
          title: formTitle.trim(),
          username: formUsername.trim(),
          password: formPassword,
          totpSecret: formTotp.trim() || undefined,
          createdAt: selected.payload.createdAt,
          updatedAt: now
        }

        const pushdrop = new PushDrop(walletClient)
        const encrypted = (await walletClient.encrypt({
          plaintext: Utils.toArray(JSON.stringify(payload), 'utf8'),
          protocolID: PROTOCOL_ID,
          keyID,
        })).ciphertext

        const lockingScript = await pushdrop.lock(
          [encrypted],
          PROTOCOL_ID, keyID, 'self'
        )

        const action = await walletClient.createAction({
          outputs: [{
            lockingScript: lockingScript.toHex(),
            satoshis: satoshiAmount,
            basket: PASSWORD_BASKET,
            customInstructions: JSON.stringify({ keyID }),
            outputDescription: `Password entry (updated): ${payload.title}`
          }],
          options: { randomizeOutputs: false, acceptDelayedBroadcast: true },
          description: `Create updated password entry for ${payload.title}`
        })

        // Replace in local state
        const newEntry: PasswordEntry = {
          sats: satoshiAmount,
          outpoint: `${action.txid}.0`,
          lockingScript: lockingScript.toHex(),
          beef: action.tx,
          keyID,
          payload
        }

        setEntries(prev => [newEntry, ...prev.filter(e => e !== selected)])
        setEditOpen(false)
        setSelected(null)
        setRevealedEntries(prev => {
          if (!prev[selected.outpoint]) return prev
          const next = { ...prev }
          delete next[selected.outpoint]
          return next
        })
        showToast('Password updated', 'success')
      }

      // Now spend old, do not link transactions together for security
      {
        const { signableTransaction } = await walletClient.createAction({
          description: `Update password (spend old): ${selected.payload.title}`,
          inputBEEF: selected.beef,
          inputs: [{
            inputDescription: 'Spend old password entry',
            outpoint: selected.outpoint,
            unlockingScriptLength: 73
          }],
          options: { acceptDelayedBroadcast: true, randomizeOutputs: false }
        })
        if (!signableTransaction) throw new Error('Failed to create signable transaction (edit/spend)')
        const partialTx = Transaction.fromBEEF(signableTransaction.tx)
        const unlocker = new PushDrop(walletClient).unlock(
          PROTOCOL_ID, selected.keyID, 'self', 'all', false, selected.sats, LockingScript.fromHex(selected.lockingScript)
        )
        const unlockingScript = await unlocker.sign(partialTx, 0)
        await walletClient.signAction({
          reference: signableTransaction.reference,
          spends: { 0: { unlockingScript: unlockingScript.toHex() } }
        })
      }
    } catch (e: any) {
      showToast(e.message || 'Failed to update password', 'error')
      console.error(e)
    } finally {
      setEditing(false)
    }
  }

  // ----- QR scan -----

  const onQrResult = (data?: string | null) => {
    if (!data) return
    const parsed = parseOtpauth(data)
    if (parsed?.totpSecret) {
      setFormTotp(parsed.totpSecret)
      if (!formTitle && parsed.issuer) setFormTitle(parsed.issuer)
      showToast('TOTP secret captured', 'success')
      setQrOpen(false)
    } else {
      showToast('Not a valid otpauth:// TOTP QR', 'error')
    }
  }

  // ----- Menu -----

  const openMenu = (e: React.MouseEvent<HTMLElement>, entry: PasswordEntry) => {
    setSelected(entry)
    setMenuAnchor(e.currentTarget)
  }
  const closeMenu = () => setMenuAnchor(null)

  // ----- UI -----

  return (
    <>
      <NoMncModal appName='Passkey Vault' open={isMncMissing} onClose={() => setIsMncMissing(false)} />

      <AppBar position='fixed' color='transparent' elevation={0}>
        <Toolbar sx={{ gap: 1.5 }}>
          <Typography variant='h6' component='div' sx={{ fontWeight: 600, letterSpacing: '-0.01em' }}>
            Passkey Vault
          </Typography>
          <Chip
            label='BRC-100 • PushDrop'
            color='secondary'
            variant='outlined'
            sx={{ display: { xs: 'none', sm: 'inline-flex' }, fontWeight: 500 }}
          />
          <Box sx={{ flexGrow: 1 }} />
          <Tooltip title={vaultVisible ? 'Lock vault' : 'Unlock vault'}>
            <IconButton
              color='inherit'
              onClick={toggleVaultVisibility}
              sx={{ display: { xs: 'none', sm: 'inline-flex' } }}
            >
              {vaultVisible ? <VisibilityOffIcon /> : <VisibilityIcon />}
            </IconButton>
          </Tooltip>
          <Tooltip title='Open repository'>
            <span>
              <GitHubIconStyle size='large' onClick={() => window.open('https://github.com/p2ppsr/passwords-app', '_blank')}>
                <GitHubIcon />
              </GitHubIconStyle>
            </span>
          </Tooltip>
          <Button
            variant='contained'
            startIcon={<AddIcon />}
            onClick={openCreate}
            sx={{ display: { xs: 'none', sm: 'inline-flex' }, ml: 1 }}
          >
            New credential
          </Button>
        </Toolbar>
      </AppBar>
      <AppBarPlaceholder />

      <Shell>
        <HeroCard elevation={0}>
          <Stack spacing={3} direction={{ xs: 'column', md: 'row' }} alignItems={{ md: 'center' }}>
            <Stack spacing={1.5} flex={1}>
              <Typography variant='overline' color='text.secondary' sx={{ letterSpacing: '0.32em', textTransform: 'uppercase' }}>
                End-to-end encrypted
              </Typography>
              <Typography variant={small ? 'h4' : 'h3'} sx={{ fontWeight: 600, lineHeight: 1.1 }}>
                Your credentials, sealed in a quantum-resistant vault.
              </Typography>
              <Typography variant='body1' color='text.secondary'>
                Passkey Vault stores every password as its own on-chain artifact with optional TOTP secrets for live 2FA codes anywhere.
              </Typography>
            </Stack>
            <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5} alignSelf={{ xs: 'stretch', md: 'center' }}>
              <Button variant='contained' startIcon={<AddIcon />} onClick={openCreate}>
                Create credential
              </Button>
              <Button
                variant='outlined'
                startIcon={vaultVisible ? <VisibilityOffIcon /> : <VisibilityIcon />}
                onClick={toggleVaultVisibility}
              >
                {vaultVisible ? 'Lock vault' : 'Unlock vault'}
              </Button>
            </Stack>
          </Stack>
        </HeroCard>

        <SearchSurface
          elevation={0}
          sx={{
            gridTemplateColumns: { xs: '1fr', md: 'minmax(0, 1fr) minmax(280px, 420px)' },
            alignItems: 'center'
          }}
        >
          <Stack spacing={0.5}>
            <Typography variant='subtitle1' sx={{ fontWeight: 600 }}>
              Find stored credentials
            </Typography>
            <Typography variant='body2' color='text.secondary'>
              Filter by site, username, issuer, or authenticator label to surface the entry you need.
            </Typography>
          </Stack>
          <TextField
            fullWidth
            placeholder='Search your vault...'
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            InputProps={{
              startAdornment: (
                <InputAdornment position='start'>
                  <SearchIcon />
                </InputAdornment>
              )
            }}
          />
        </SearchSurface>

        {loadingList ? (
        <LoadingBar />
      ) : (
        <>
          {entries.length === 0 ? (
            <NoItems container direction='column' justifyContent='center' alignItems='center'>
              <Grid item>
                <Typography variant='h4' gutterBottom>
                  Build your first vault entry
                </Typography>
                <Typography color='text.secondary'>
                  Save a credential to see it appear here with instant encryption and chained backups.
                </Typography>
              </Grid>
              <Grid item sx={{ pt: 4 }}>
                <Button variant='contained' startIcon={<AddIcon />} onClick={openCreate}>
                  Create credential
                </Button>
              </Grid>
            </NoItems>
          ) : (
            <Box sx={{ position: 'relative' }}>
              <List
                dense={small}
                sx={{
                  display: 'flex',
                  flexDirection: 'column',
                  gap: small ? 1.5 : 2.5,
                  filter: vaultVisible ? 'none' : 'blur(12px)',
                  opacity: vaultVisible ? 1 : 0.3,
                  pointerEvents: vaultVisible ? 'auto' : 'none',
                  transition: 'filter 160ms ease, opacity 160ms ease'
                }}
              >
                {visible.map((e, i) => {
                  const hasTotp = !!e.payload.totpSecret
                  const totp = hasTotp ? totpCodes[e.outpoint] : undefined
                  const code = totp?.code ?? ''
                  const remaining = totp?.remaining ?? (hasTotp ? fallbackRemaining : 0)
                  const entryVisible = Boolean(revealedEntries[e.outpoint])
                  const displayedCode = vaultVisible && entryVisible ? (code || '------') : '••••••'
                  const displayedCountdown = vaultVisible && entryVisible
                    ? (remaining > 0 ? `T-${remaining}s` : 'Unavailable')
                    : 'Hidden'
                  const createdLabel = formatTimestamp(e.payload.createdAt)
                  const updatedLabel = formatTimestamp(e.payload.updatedAt)
                  return (
                    <ListItem
                      key={e.outpoint + i}
                      disableGutters
                      sx={{ px: 0, alignItems: 'stretch' }}
                    >
                      <PasswordCard>
                        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 1, flexWrap: 'wrap' }}>
                          <Typography variant='subtitle1' sx={{ fontWeight: 600 }}>
                            {e.payload.title}
                          </Typography>
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, flexWrap: 'wrap' }}>
                            {hasTotp && (
                              <>
                                <Chip
                                  size='small'
                                  label={displayedCode}
                                  variant='outlined'
                                  sx={{
                                    fontFamily: 'monospace',
                                    letterSpacing: '0.12em',
                                    borderColor: (theme) => alpha(theme.palette.success.light, 0.55),
                                    color: (theme) => theme.palette.success.light,
                                    bgcolor: (theme) => alpha(theme.palette.success.light, entryVisible ? 0.18 : 0.08)
                                  }}
                                />
                                <Chip
                                  size='small'
                                  label={displayedCountdown}
                                  sx={{
                                    fontFamily: 'monospace',
                                    letterSpacing: '0.12em',
                                    color: (theme) => theme.palette.info.light,
                                    bgcolor: (theme) => alpha(theme.palette.info.light, entryVisible ? 0.12 : 0.06)
                                  }}
                                />
                              </>
                            )}
                            <Tooltip title={entryVisible ? 'Hide password' : 'Show password'}>
                              <span>
                                <IconButton
                                  size='small'
                                  onClick={() => toggleEntryVisibility(e.outpoint)}
                                  disabled={!vaultVisible}
                                >
                                  {entryVisible ? <VisibilityOffIcon fontSize='small' /> : <VisibilityIcon fontSize='small' />}
                                </IconButton>
                              </span>
                            </Tooltip>
                            <Tooltip title='More options'>
                              <IconButton size='small' onClick={(ev) => openMenu(ev, e)}>
                                <MoreVertIcon fontSize='small' />
                              </IconButton>
                            </Tooltip>
                          </Box>
                        </Box>
                        <Typography variant='body2' color='text.secondary'>
                          {e.payload.username}
                        </Typography>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, flexWrap: 'wrap' }}>
                          <PasswordValue>
                            {vaultVisible && entryVisible ? e.payload.password : mask(e.payload.password)}
                          </PasswordValue>
                          <Tooltip title={vaultVisible && entryVisible ? 'Copy password' : 'Reveal password to copy'}>
                            <span>
                              <IconButton
                                size='small'
                                onClick={() => handleCopy(e.payload.password, 'Password copied')}
                                disabled={!(vaultVisible && entryVisible)}
                              >
                                <ContentCopyIcon fontSize='small' />
                              </IconButton>
                            </span>
                          </Tooltip>
                          {hasTotp && (
                            <Tooltip title={vaultVisible && entryVisible ? 'Copy TOTP code' : 'Reveal password to copy'}>
                              <span>
                                <IconButton
                                  size='small'
                                  onClick={() => handleCopy(code, 'TOTP code copied')}
                                  disabled={!(vaultVisible && entryVisible && code)}
                                >
                                  <ContentCopyIcon fontSize='small' />
                                </IconButton>
                              </span>
                            </Tooltip>
                          )}
                        </Box>
                        {(e.payload.issuer || e.payload.accountName) && (
                          <Typography variant='caption' color='text.secondary'>
                            {e.payload.issuer ? `${e.payload.issuer} • ` : ''}{e.payload.accountName || ''}
                          </Typography>
                        )}
                        <Stack direction='row' spacing={1.5} flexWrap='wrap' sx={{ mt: 1 }}>
                          {createdLabel && (
                            <Typography variant='caption' color='text.secondary'>
                              Saved {createdLabel}
                            </Typography>
                          )}
                          {updatedLabel && (
                            <Typography variant='caption' color='text.secondary'>
                              Updated {updatedLabel}
                            </Typography>
                          )}
                          <Chip
                            size='small'
                            label={`${e.sats ?? 0} sats`}
                            sx={{
                              fontSize: '0.65rem',
                              letterSpacing: '0.08em',
                              bgcolor: (theme) => alpha(theme.palette.primary.main, 0.12),
                              color: (theme) => theme.palette.primary.main,
                              border: (theme) => `1px solid ${alpha(theme.palette.primary.main, 0.24)}`
                            }}
                          />
                        </Stack>
                      </PasswordCard>
                    </ListItem>
                  )
                })}
              </List>
              {!vaultVisible && (
                <Box
                  sx={{
                    position: 'absolute',
                    inset: 0,
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'center',
                    justifyContent: 'center',
                    textAlign: 'center',
                    gap: 2,
                    px: 3,
                    py: 6,
                    borderRadius: 2,
                    bgcolor: theme => theme.palette.mode === 'dark' ? 'rgba(0,0,0,0.7)' : 'rgba(255,255,255,0.76)',
                    backdropFilter: 'blur(2px)'
                  }}
                >
                  <Typography variant='h6'>Vault locked</Typography>
                  <Typography
                    variant='body2'
                    sx={{ color: theme => theme.palette.mode === 'dark' ? 'rgba(255,255,255,0.75)' : 'rgba(30,41,59,0.7)' }}
                  >
                    Unlock to review secrets. Viewing keeps sensitive data off-screen by default.
                  </Typography>
                  <Button variant='contained' startIcon={<VisibilityIcon />} onClick={showVault}>
                    Unlock vault
                  </Button>
                </Box>
              )}
            </Box>
          )}
        </>
      )}

        {entries.length >= 1 && (
          <AddMoreFab color='primary' onClick={openCreate}><AddIcon /></AddMoreFab>
        )}
      </Shell>

      {/* Menu for item actions */}
      <Menu anchorEl={menuAnchor} open={Boolean(menuAnchor)} onClose={closeMenu}>
        <MenuItem onClick={() => { closeMenu(); if (selected) openEdit(selected) }}>
          <EditIcon fontSize='small' style={{ marginRight: 8 }} />
          Edit credential
        </MenuItem>
        <MenuItem onClick={() => { closeMenu(); if (selected) requestDelete(selected) }}>
          <DeleteIcon fontSize='small' style={{ marginRight: 8 }} />
          Delete credential
        </MenuItem>
      </Menu>

      {/* CREATE DIALOG */}
      <Dialog open={createOpen} onClose={() => setCreateOpen(false)} fullWidth maxWidth='sm'>
        <form onSubmit={handleCreate}>
          <DialogTitle>Add Credential</DialogTitle>
          <DialogContent>
            <DialogContentText paragraph>
              Store a credential, encrypted to your identity. Optionally attach a TOTP secret for rolling authentication codes.
            </DialogContentText>
            <Grid container spacing={2}>
              <Grid item xs={12}>
                <TextField label='Title / Site' fullWidth value={formTitle} onChange={e => setFormTitle(e.target.value)} autoFocus />
              </Grid>
              <Grid item xs={12} sm={6}>
                <TextField label='Username' fullWidth value={formUsername} onChange={e => setFormUsername(e.target.value)} />
              </Grid>
              <Grid item xs={12} sm={6}>
                <TextField
                  label='Password'
                  fullWidth
                  value={formPassword}
                  onChange={e => setFormPassword(e.target.value)}
                  type={formPasswordVisible ? 'text' : 'password'}
                  InputProps={{
                    endAdornment: (
                      <InputAdornment position='end'>
                        <IconButton onClick={() => setFormPasswordVisible(v => !v)}>
                          {formPasswordVisible ? <VisibilityOffIcon /> : <VisibilityIcon />}
                        </IconButton>
                      </InputAdornment>
                    )
                  }}
                />
              </Grid>
              <Grid item xs={12} sm={8}>
                <TextField
                  label='TOTP Secret (base32)'
                  fullWidth
                  value={formTotp}
                  onChange={e => setFormTotp(e.target.value.replace(/\s+/g, ''))}
                  placeholder='Optional'
                />
              </Grid>
              <Grid item xs={12} sm={4}>
                <Button
                  onClick={() => setQrOpen(true)}
                  startIcon={<QrCodeScannerIcon />}
                  fullWidth
                  variant='outlined'
                  sx={{ height: '100%' }}
                >
                  Scan authenticator QR
                </Button>
              </Grid>
            </Grid>
          </DialogContent>
          {creating ? <LoadingBar /> : (
            <DialogActions>
              <Button onClick={() => setCreateOpen(false)}>Cancel</Button>
              <Button type='submit' variant='contained'>Save to vault</Button>
            </DialogActions>
          )}
        </form>
      </Dialog>

      {/* EDIT DIALOG */}
      <Dialog open={editOpen} onClose={() => setEditOpen(false)} fullWidth maxWidth='sm'>
        <form onSubmit={handleEdit}>
          <DialogTitle>Edit Credential</DialogTitle>
          <DialogContent>
            <Grid container spacing={2}>
              <Grid item xs={12}>
                <TextField label='Title / Site' fullWidth value={formTitle} onChange={e => setFormTitle(e.target.value)} autoFocus />
              </Grid>
              <Grid item xs={12} sm={6}>
                <TextField label='Username' fullWidth value={formUsername} onChange={e => setFormUsername(e.target.value)} />
              </Grid>
              <Grid item xs={12} sm={6}>
                <TextField
                  label='Password'
                  fullWidth
                  value={formPassword}
                  onChange={e => setFormPassword(e.target.value)}
                  type={formPasswordVisible ? 'text' : 'password'}
                  InputProps={{
                    endAdornment: (
                      <InputAdornment position='end'>
                        <IconButton onClick={() => setFormPasswordVisible(v => !v)}>
                          {formPasswordVisible ? <VisibilityOffIcon /> : <VisibilityIcon />}
                        </IconButton>
                      </InputAdornment>
                    )
                  }}
                />
              </Grid>
              <Grid item xs={12} sm={8}>
                <TextField
                  label='TOTP Secret (base32)'
                  fullWidth
                  value={formTotp}
                  onChange={e => setFormTotp(e.target.value.replace(/\s+/g, ''))}
                  placeholder='Optional'
                />
              </Grid>
              <Grid item xs={12} sm={4}>
                <Button
                  onClick={() => setQrOpen(true)}
                  startIcon={<QrCodeScannerIcon />}
                  fullWidth
                  variant='outlined'
                  sx={{ height: '100%' }}
                >
                  Scan authenticator QR
                </Button>
              </Grid>
            </Grid>
          </DialogContent>
          {editing ? <LoadingBar /> : (
            <DialogActions>
              <Button onClick={() => setEditOpen(false)}>Cancel</Button>
              <Button type='submit' variant='contained'>Update entry</Button>
            </DialogActions>
          )}
        </form>
      </Dialog>

      {/* DELETE CONFIRM */}
      <Dialog open={confirmDeleteOpen} onClose={() => setConfirmDeleteOpen(false)}>
        <DialogTitle>Remove “{selected?.payload.title}” from the vault?</DialogTitle>
        <DialogContent>
          <DialogContentText>
            This permanently deletes the credential and its encrypted payload from your on-chain vault.
          </DialogContentText>
        </DialogContent>
        {deleting ? <LoadingBar /> : (
          <DialogActions>
            <Button onClick={() => setConfirmDeleteOpen(false)}>Cancel</Button>
            <Button color='error' variant='contained' onClick={() => void handleDelete()}>Delete</Button>
          </DialogActions>
        )}
      </Dialog>

      {/* QR SCAN (TOTP) */}
      <Dialog open={qrOpen} onClose={() => setQrOpen(false)} fullWidth maxWidth='xs'>
        <DialogTitle>Scan authenticator QR</DialogTitle>
        <DialogContent>
          <DialogContentText paragraph>
            Point your camera at an <code>otpauth://</code> QR code from your authenticator app setup screen.
          </DialogContentText>
          <Box sx={{ borderRadius: 1, overflow: 'hidden' }}>
            <QrReader
              constraints={{ facingMode: 'environment' }}
              onResult={(result, error) => {
                if (!!result) onQrResult(result.getText())
                if (!!error) { /* ignore per-frame decode errors */ }
              }}
              containerStyle={{ width: '100%', minHeight: 240 }}
              videoStyle={{ width: '100%' }}
            />
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setQrOpen(false)}>Close</Button>
        </DialogActions>
      </Dialog>

      <Box
        component='footer'
        sx={{
          mt: 8,
          borderTop: (theme) => `1px solid ${alpha(theme.palette.primary.light, 0.18)}`,
          backgroundColor: (theme) => alpha(theme.palette.background.paper, 0.65)
        }}
      >
        <Shell sx={{ paddingTop: small ? 3 : 4, paddingBottom: small ? 4 : 5 }}>
          <Typography variant='subtitle2' gutterBottom>
            Legal Notice &amp; Liability Disclaimer
          </Typography>
          <Typography variant='body2' color='text.secondary' paragraph>
            Passkey Vault is distributed under the Open BSV License strictly on an "AS IS" basis.
            To the maximum extent permitted by applicable law, the authors, maintainers, and contributors
            expressly disclaim all warranties and conditions of any kind, whether express or implied,
            including but not limited to merchantability, fitness for a particular purpose, non-infringement,
            data security, and uninterrupted or error-free operation.
          </Typography>
          <Typography variant='body2' color='text.secondary'>
            You assume all risk for your use of this software. Under no circumstances shall the authors,
            maintainers, contributors, or rights holders be liable for any direct, indirect, incidental,
            special, exemplary, or consequential damages, losses, or claims arising from or in connection
            with the software, your data, your credentials, or any transaction performed with it, even if
            advised of the possibility of such damages. By continuing, you acknowledge that you have read,
            understood, and agree to the Open BSV License and this full waiver of liability.
          </Typography>
        </Shell>
      </Box>
      <Snackbar
        open={Boolean(toast)}
        autoHideDuration={4000}
        onClose={handleToastClose}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      >
        {toast ? (
          <Alert onClose={handleToastClose} severity={toast.severity} variant='filled' sx={{ width: '100%' }}>
            {toast.message}
          </Alert>
        ) : null}
      </Snackbar>
    </>
  )
}

export default App
