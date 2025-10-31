import React from 'react'
import ReactDOM from 'react-dom'
import { CssBaseline } from '@mui/material'
import { ThemeProvider } from '@mui/material/styles'
import App from './App'
import vaultTheme from './theme'

const rootElement = document.getElementById('root')

if (rootElement === null) {
  throw new Error('Failed to find the root element')
}

ReactDOM.render(
  <ThemeProvider theme={vaultTheme}>
    <CssBaseline />
    <App />
  </ThemeProvider>,
  rootElement
)
