/* eslint-disable @typescript-eslint/no-non-null-assertion */
/**
 * Metanet Password Manager (BSV / PushDrop / BRC100)
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

import React, { useEffect, useMemo, useRef, useState, type FormEvent } from 'react'

import {
  AppBar, Toolbar, Typography, IconButton, Grid, Button, Fab, LinearProgress, TextField,
  Dialog, DialogTitle, DialogContent, DialogActions, DialogContentText, List, ListItem,
  ListItemText, ListItemIcon, Checkbox, InputAdornment, useMediaQuery, Menu, MenuItem,
  Chip, Box, Tooltip
} from '@mui/material'
import { styled } from '@mui/system'
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
  type WalletOutput, type WalletProtocol
} from '@bsv/sdk'

import { authenticator } from 'otplib'
import { QrReader } from 'react-qr-reader'

import './App.scss'

// ------------- Constants / Protocol -------------

const PASS_PROTO_ADDR = '1PwdMgrSgEwMNetSecureVaultXXXXXXXX' // namespace string; arbitrary label used in PushDrop payload
const PROTOCOL_ID: WalletProtocol = [0, 'password manager']
const KEY_ID = '1'
const DEFAULT_CREATE_AMOUNT = 1 // sat
const PASSWORD_BASKET = 'password entries'

// ------------- Styling -------------

const AppBarPlaceholder = styled('div')({ height: '4em' })
const AddMoreFab = styled(Fab)({
  position: 'fixed',
  right: '1em',
  bottom: '1em',
  zIndex: 10
})
const LoadingBar = styled(LinearProgress)({ margin: '1em' })
const GitHubIconStyle = styled(IconButton)({ color: '#ffffff' })
const NoItems = styled(Grid)({ margin: 'auto', textAlign: 'center', marginTop: '5em' })
const Row = styled('div')({ display: 'flex', gap: '0.75rem', alignItems: 'center' })

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
  lockingScript: string
  beef: number[] | undefined
  payload: PasswordPayload
}

// ------------- Wallet -------------

const walletClient = new WalletClient()

// ------------- Helpers -------------

function mask(val: string): string {
  if (!val) return ''
  if (val.length <= 4) return '•'.repeat(val.length)
  return `${'•'.repeat(Math.max(0, val.length - 4))}${val.slice(-4)}`
}

function copy(text: string) {
  navigator.clipboard.writeText(text).then(() => {
    alert('Copied to clipboard')
  }).catch(() => {
    alert('Failed to copy')
  })
}

function isValidBase32(s: string): boolean {
  // Basic sanity; otplib will further validate at use
  return /^[A-Z2-7]+=*$/i.test(s.replace(/\s+/g, ''))
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

const buildEncryptedFields = async (
  payload: PasswordPayload
): Promise<number[]> => {
  const encrypted = (await walletClient.encrypt({
    plaintext: Utils.toArray(JSON.stringify(payload), 'utf8'),
    protocolID: PROTOCOL_ID,
    keyID: KEY_ID
  })).ciphertext
  // PushDrop fields; first is protocol namespace marker, second is encrypted blob
  return [Utils.toArray(PASS_PROTO_ADDR, 'utf8') as unknown as number[], encrypted].flat() as unknown as number[]
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
  const [formSats, setFormSats] = useState<number>(DEFAULT_CREATE_AMOUNT)

  // UI toggles
  const [revealPassword, setRevealPassword] = useState<boolean>(false)

  // Responsive layout
  const small = useMediaQuery('(max-width:600px)')

  // TOTP live code handling
  const [tick, setTick] = useState<number>(0) // force re-render each second
  useEffect(() => {
    const i = setInterval(() => setTick(t => t + 1), 1000)
    return () => clearInterval(i)
  }, [])

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
        limit: 1000
      })

      const results = await Promise.all(
        res.outputs.map(async (wo: WalletOutput) => {
          try {
            const txid = wo.outpoint.split('.')[0]
            const tx = Transaction.fromBEEF(res.BEEF as number[], txid)
            const lockingScript = tx!.outputs[0].lockingScript
            const decoded = PushDrop.decode(lockingScript)
            const encryptedBlob = decoded.fields[1]
            const dec = await walletClient.decrypt({
              ciphertext: encryptedBlob,
              protocolID: PROTOCOL_ID,
              keyID: KEY_ID
            })
            const payload: PasswordPayload = JSON.parse(Utils.toUTF8(dec.plaintext))

            const entry: PasswordEntry = {
              sats: wo.satoshis ?? 0,
              outpoint: `${txid}.0`,
              lockingScript: lockingScript.toHex(),
              beef: res.BEEF,
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
    } catch (e: any) {
      const code = e?.code
      if (code !== 'ERR_NO_METANET_IDENTITY') {
        alert(`Failed to load password entries: ${e.message}`)
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

  // ----- TOTP helpers -----

  function totpFor(secret?: string) {
    if (!secret || !isValidBase32(secret)) return { code: '', remaining: 0 }
    try {
      const epoch = Math.floor(Date.now() / 1000)
      const step = 30
      const remaining = step - (epoch % step)
      const code = authenticator.generate(secret)
      return { code, remaining }
    } catch {
      return { code: '', remaining: 0 }
    }
  }

  // ----- Create -----

  const openCreate = () => {
    setFormTitle('')
    setFormUsername('')
    setFormPassword('')
    setFormTotp('')
    setFormSats(DEFAULT_CREATE_AMOUNT)
    setRevealPassword(false)
    setCreateOpen(true)
  }

  const handleCreate = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    try {
      if (!formTitle.trim()) return alert('Enter a title (site / label)')
      if (!formUsername.trim()) return alert('Enter a username')
      if (!formPassword) return alert('Enter a password')
      if (formSats < 1 || isNaN(formSats)) return alert('Amount must be at least 1 satoshi')

      if (formTotp && !isValidBase32(formTotp)) return alert('TOTP secret must be base32')

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
      const fields = await (async () => {
        const encrypted = (await walletClient.encrypt({
          plaintext: Utils.toArray(JSON.stringify(payload), 'utf8'),
          protocolID: PROTOCOL_ID,
          keyID: KEY_ID
        })).ciphertext
        return [
          Utils.toArray(PASS_PROTO_ADDR, 'utf8'),
          encrypted
        ]
      })()

      const lockingScript = await pushdrop.lock(fields, PROTOCOL_ID, KEY_ID, 'self')

      const action = await walletClient.createAction({
        outputs: [{
          lockingScript: lockingScript.toHex(),
          satoshis: Number(formSats),
          basket: PASSWORD_BASKET,
          outputDescription: `Password entry: ${payload.title}`
        }],
        options: { randomizeOutputs: false, acceptDelayedBroadcast: true },
        description: `Create a password entry for ${payload.title}`
      })

      const newEntry: PasswordEntry = {
        sats: Number(formSats),
        outpoint: `${action.txid}.0`,
        lockingScript: lockingScript.toHex(),
        beef: action.tx,
        payload
      }

      setEntries(prev => [newEntry, ...prev])
      setCreateOpen(false)
      alert('Password saved')
    } catch (e: any) {
      alert(e.message || 'Failed to create password entry')
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
      const { beef, sats } = selected

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
        PROTOCOL_ID, KEY_ID, 'self', 'all', false, sats, LockingScript.fromHex(selected.lockingScript)
      )
      const unlockingScript = await unlocker.sign(partialTx, 0)

      await walletClient.signAction({
        reference: signableTransaction.reference,
        spends: { 0: { unlockingScript: unlockingScript.toHex() } }
      })

      setEntries(prev => prev.filter(e => e !== selected))
      setSelected(null)
      setConfirmDeleteOpen(false)
      alert('Password deleted')
    } catch (e: any) {
      alert(e.message || 'Failed to delete password')
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
    setFormSats(entry.sats || DEFAULT_CREATE_AMOUNT)
    setRevealPassword(false)
    setEditOpen(true)
  }

  const handleEdit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    if (!selected) return
    try {
      if (!formTitle.trim()) return alert('Enter a title (site / label)')
      if (!formUsername.trim()) return alert('Enter a username')
      if (!formPassword) return alert('Enter a password')
      if (formTotp && !isValidBase32(formTotp)) return alert('TOTP secret must be base32')
      if (formSats < 1 || isNaN(formSats)) return alert('Amount must be at least 1 satoshi')

      setEditing(true)

      // 1) Spend old
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
          PROTOCOL_ID, KEY_ID, 'self', 'all', false, selected.sats, LockingScript.fromHex(selected.lockingScript)
        )
        const unlockingScript = await unlocker.sign(partialTx, 0)
        await walletClient.signAction({
          reference: signableTransaction.reference,
          spends: { 0: { unlockingScript: unlockingScript.toHex() } }
        })
      }

      // 2) Create new
      {
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
          keyID: KEY_ID
        })).ciphertext

        const lockingScript = await pushdrop.lock(
          [Utils.toArray(PASS_PROTO_ADDR, 'utf8'), encrypted],
          PROTOCOL_ID, KEY_ID, 'self'
        )

        const action = await walletClient.createAction({
          outputs: [{
            lockingScript: lockingScript.toHex(),
            satoshis: Number(formSats),
            basket: PASSWORD_BASKET,
            outputDescription: `Password entry (updated): ${payload.title}`
          }],
          options: { randomizeOutputs: false, acceptDelayedBroadcast: true },
          description: `Create updated password entry for ${payload.title}`
        })

        // Replace in local state
        const newEntry: PasswordEntry = {
          sats: Number(formSats),
          outpoint: `${action.txid}.0`,
          lockingScript: lockingScript.toHex(),
          beef: action.tx,
          payload
        }

        setEntries(prev => [newEntry, ...prev.filter(e => e !== selected)])
        setEditOpen(false)
        setSelected(null)
        alert('Password updated')
      }
    } catch (e: any) {
      alert(e.message || 'Failed to update password')
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
      alert('TOTP secret captured')
      setQrOpen(false)
    } else {
      alert('Not a valid otpauth:// TOTP QR')
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
      <NoMncModal appName='Metanet Password Manager' open={isMncMissing} onClose={() => setIsMncMissing(false)} />

      <AppBar position='static'>
        <Toolbar>
          <Typography variant='h6' component='div' sx={{ flexGrow: 1 }}>
            Metanet Password Manager
          </Typography>
          <GitHubIconStyle onClick={() => window.open('https://github.com/p2ppsr/todo-ts', '_blank')}>
            <GitHubIcon />
          </GitHubIconStyle>
        </Toolbar>
      </AppBar>
      <AppBarPlaceholder />

      <Box sx={{ p: small ? 1.5 : 3 }}>
        {/* Search */}
        <TextField
          fullWidth
          placeholder='Search by title, username, issuer, account...'
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
      </Box>

      {loadingList ? (
        <LoadingBar />
      ) : (
        <>
          {entries.length === 0 ? (
            <NoItems container direction='column' justifyContent='center' alignItems='center'>
              <Grid item>
                <Typography variant='h4' gutterBottom>No Passwords Yet</Typography>
                <Typography color='textSecondary'>Use the button below to add one</Typography>
              </Grid>
              <Grid item sx={{ pt: '2.5em', mb: '1em' }}>
                <Fab color='primary' onClick={openCreate}><AddIcon /></Fab>
              </Grid>
            </NoItems>
          ) : (
            <List dense={small}>
              {visible.map((e, i) => {
                const hasTotp = !!e.payload.totpSecret
                const { code, remaining } = hasTotp ? totpFor(e.payload.totpSecret) : { code: '', remaining: 0 }
                return (
                  <ListItem
                    key={e.outpoint + i}
                    sx={{
                      borderBottom: '1px solid rgba(0,0,0,0.06)',
                      alignItems: 'flex-start',
                      py: small ? 1 : 1.5
                    }}
                    secondaryAction={
                      <>
                        <Tooltip title="More">
                          <IconButton edge='end' onClick={(ev) => openMenu(ev, e)}><MoreVertIcon /></IconButton>
                        </Tooltip>
                      </>
                    }
                  >
                    <ListItemIcon sx={{ minWidth: 40 }}>
                      <Checkbox edge='start' tabIndex={-1} disableRipple checked={hasTotp} />
                    </ListItemIcon>

                    <ListItemText
                      primary={
                        <Row>
                          <Typography variant='subtitle1' sx={{ fontWeight: 600 }}>{e.payload.title}</Typography>
                          {hasTotp && (
                            <Chip
                              size='small'
                              label={code || '••••••'}
                              variant='outlined'
                            />
                          )}
                          {hasTotp && (
                            <Chip
                              size='small'
                              label={`T-${remaining}s`}
                            />
                          )}
                          <Chip size='small' label={`${e.sats} sats`} />
                        </Row>
                      }
                      secondary={
                        <Box sx={{ mt: 0.5 }}>
                          <Row>
                            <Typography variant='body2' color='textSecondary'>
                              {e.payload.username}
                            </Typography>
                            <Tooltip title={revealPassword ? 'Hide password' : 'Show password'}>
                              <IconButton size='small' onClick={() => setRevealPassword(v => !v)}>
                                {revealPassword ? <VisibilityOffIcon /> : <VisibilityIcon />}
                              </IconButton>
                            </Tooltip>
                            <Typography variant='body2' sx={{ fontFamily: 'monospace' }}>
                              {revealPassword ? e.payload.password : mask(e.payload.password)}
                            </Typography>
                            <Tooltip title='Copy password'>
                              <IconButton size='small' onClick={() => copy(e.payload.password)}>
                                <ContentCopyIcon fontSize='small' />
                              </IconButton>
                            </Tooltip>
                            {hasTotp && code && (
                              <Tooltip title='Copy TOTP code'>
                                <IconButton size='small' onClick={() => copy(code)}>
                                  <ContentCopyIcon fontSize='small' />
                                </IconButton>
                              </Tooltip>
                            )}
                          </Row>
                          {(e.payload.issuer || e.payload.accountName) && (
                            <Typography variant='caption' color='textSecondary'>
                              {e.payload.issuer ? `${e.payload.issuer} • ` : ''}{e.payload.accountName || ''}
                            </Typography>
                          )}
                        </Box>
                      }
                    />
                  </ListItem>
                )
              })}
            </List>
          )}
        </>
      )}

      {entries.length >= 1 && (
        <AddMoreFab color='primary' onClick={openCreate}><AddIcon /></AddMoreFab>
      )}

      {/* Menu for item actions */}
      <Menu anchorEl={menuAnchor} open={Boolean(menuAnchor)} onClose={closeMenu}>
        <MenuItem onClick={() => { closeMenu(); if (selected) openEdit(selected) }}>
          <EditIcon fontSize='small' style={{ marginRight: 8 }} />
          Edit
        </MenuItem>
        <MenuItem onClick={() => { closeMenu(); if (selected) requestDelete(selected) }}>
          <DeleteIcon fontSize='small' style={{ marginRight: 8 }} />
          Delete
        </MenuItem>
      </Menu>

      {/* CREATE DIALOG */}
      <Dialog open={createOpen} onClose={() => setCreateOpen(false)} fullWidth maxWidth='sm'>
        <form onSubmit={handleCreate}>
          <DialogTitle>Add Password</DialogTitle>
          <DialogContent>
            <DialogContentText paragraph>
              Store a credential, encrypted to your identity. Optionally attach a TOTP secret for codes.
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
                  type={revealPassword ? 'text' : 'password'}
                  InputProps={{
                    endAdornment: (
                      <InputAdornment position='end'>
                        <IconButton onClick={() => setRevealPassword(v => !v)}>
                          {revealPassword ? <VisibilityOffIcon /> : <VisibilityIcon />}
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
                  Scan QR
                </Button>
              </Grid>
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  type='number'
                  inputProps={{ min: 1 }}
                  label='Amount to lock (sats)'
                  value={formSats}
                  onChange={(e) => setFormSats(Number(e.target.value))}
                />
              </Grid>
            </Grid>
          </DialogContent>
          {creating ? <LoadingBar /> : (
            <DialogActions>
              <Button onClick={() => setCreateOpen(false)}>Cancel</Button>
              <Button type='submit' variant='contained'>Save</Button>
            </DialogActions>
          )}
        </form>
      </Dialog>

      {/* EDIT DIALOG */}
      <Dialog open={editOpen} onClose={() => setEditOpen(false)} fullWidth maxWidth='sm'>
        <form onSubmit={handleEdit}>
          <DialogTitle>Edit Password</DialogTitle>
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
                  type={revealPassword ? 'text' : 'password'}
                  InputProps={{
                    endAdornment: (
                      <InputAdornment position='end'>
                        <IconButton onClick={() => setRevealPassword(v => !v)}>
                          {revealPassword ? <VisibilityOffIcon /> : <VisibilityIcon />}
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
                  Scan QR
                </Button>
              </Grid>
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  type='number'
                  inputProps={{ min: 1 }}
                  label='Amount to lock (sats)'
                  value={formSats}
                  onChange={(e) => setFormSats(Number(e.target.value))}
                />
              </Grid>
            </Grid>
          </DialogContent>
          {editing ? <LoadingBar /> : (
            <DialogActions>
              <Button onClick={() => setEditOpen(false)}>Cancel</Button>
              <Button type='submit' variant='contained'>Save Changes</Button>
            </DialogActions>
          )}
        </form>
      </Dialog>

      {/* DELETE CONFIRM */}
      <Dialog open={confirmDeleteOpen} onClose={() => setConfirmDeleteOpen(false)}>
        <DialogTitle>Delete “{selected?.payload.title}”?</DialogTitle>
        <DialogContent>
          <DialogContentText>
            This spends the entry’s token and removes it from the basket. Your locked satoshis are returned to you.
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
        <DialogTitle>Scan TOTP QR</DialogTitle>
        <DialogContent>
          <DialogContentText paragraph>
            Point your camera at an <code>otpauth://</code> TOTP QR code.
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
    </>
  )
}

export default App
