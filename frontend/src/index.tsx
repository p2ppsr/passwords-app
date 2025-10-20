import React from 'react'
import ReactDOM from 'react-dom'
import { CssBaseline } from '@mui/material'
import { ThemeProvider } from '@mui/material/styles'
import App from './App'
import web3Theme from './theme'

const rootElement = document.getElementById('root')

if (rootElement === null) {
  throw new Error('Failed to find the root element')
}

ReactDOM.render(
  <ThemeProvider theme={web3Theme}>
    <CssBaseline />
    <App />
  </ThemeProvider>,
  rootElement
)
