import { alpha, createTheme, responsiveFontSizes } from '@mui/material/styles'

const primaryAccent = '#4ef18d'
const baseBackground = '#050813'
const paperBackground = '#0b1529'

const rawTheme = createTheme({
  palette: {
    mode: 'dark',
    primary: {
      main: primaryAccent,
      contrastText: '#02131f'
    },
    secondary: {
      main: '#60a5fa',
      contrastText: '#031225'
    },
    background: {
      default: baseBackground,
      paper: paperBackground
    },
    divider: 'rgba(148, 163, 184, 0.24)',
    text: {
      primary: '#e6f1ff',
      secondary: '#92a4c8'
    },
    info: {
      main: '#60a5fa'
    },
    success: {
      main: '#34d399'
    },
    warning: {
      main: '#fbbf24'
    },
    error: {
      main: '#f87171'
    }
  },
  typography: {
    fontFamily: '"Inter", "Roboto", "Helvetica", "Arial", sans-serif',
    h1: { fontWeight: 700, letterSpacing: '-0.02em' },
    h2: { fontWeight: 700, letterSpacing: '-0.02em' },
    h3: { fontWeight: 600, letterSpacing: '-0.015em' },
    h4: { fontWeight: 600, letterSpacing: '-0.01em' },
    h5: { fontWeight: 600 },
    h6: { fontWeight: 600 },
    button: { textTransform: 'none', fontWeight: 600, letterSpacing: '0.05em' },
    subtitle1: { fontWeight: 500 },
    subtitle2: { fontWeight: 500, textTransform: 'uppercase', letterSpacing: '0.12em' }
  },
  shape: {
    borderRadius: 16
  },
  components: {
    MuiCssBaseline: {
      styleOverrides: {
        body: {
          background: `radial-gradient(120% 140% at 50% -10%, ${alpha(primaryAccent, 0.18)} 0%, #0b1429 52%, ${baseBackground} 100%)`,
          color: '#e6f1ff',
          minHeight: '100vh'
        },
        a: {
          color: primaryAccent,
          textDecorationColor: alpha(primaryAccent, 0.35),
          '&:hover': {
            textDecorationColor: alpha(primaryAccent, 0.8)
          }
        },
        '*::selection': {
          backgroundColor: alpha(primaryAccent, 0.35),
          color: '#03131f'
        }
      }
    },
    MuiAppBar: {
      defaultProps: { elevation: 0, color: 'transparent' },
      styleOverrides: {
        root: {
          backgroundColor: 'rgba(5, 13, 27, 0.72)',
          backdropFilter: 'blur(20px)',
          borderBottom: `1px solid ${alpha('#94a3c6', 0.18)}`
        }
      }
    },
    MuiPaper: {
      styleOverrides: {
        root: {
          backgroundImage: 'none'
        }
      }
    },
    MuiButton: {
      defaultProps: {
        disableElevation: true
      },
      styleOverrides: {
        root: {
          borderRadius: 14,
          fontWeight: 600,
          letterSpacing: '0.04em',
          paddingTop: '0.7rem',
          paddingBottom: '0.7rem',
          paddingLeft: '1.75rem',
          paddingRight: '1.75rem'
        },
        containedPrimary: {
          backgroundImage: `linear-gradient(135deg, ${alpha(primaryAccent, 0.95)} 0%, ${alpha('#67e8f9', 0.88)} 100%)`,
          color: '#04131e',
          boxShadow: `0 24px 44px ${alpha(primaryAccent, 0.32)}`,
          '&:hover': {
            boxShadow: `0 36px 72px ${alpha(primaryAccent, 0.42)}`,
            backgroundImage: `linear-gradient(135deg, ${alpha(primaryAccent, 1)} 0%, ${alpha('#7dd3fc', 0.95)} 100%)`
          }
        },
        outlined: {
          borderWidth: 1.6,
          borderColor: alpha('#60a5fa', 0.4),
          color: '#cbd5f5',
          '&:hover': {
            borderColor: alpha('#60a5fa', 0.9),
            backgroundColor: alpha('#60a5fa', 0.08)
          }
        }
      }
    },
    MuiFab: {
      styleOverrides: {
        root: {
          borderRadius: 16,
          backgroundImage: `linear-gradient(135deg, ${alpha(primaryAccent, 0.95)} 0%, ${alpha('#2dd4bf', 0.85)} 100%)`,
          color: '#04131e',
          '&:hover': {
            backgroundImage: `linear-gradient(135deg, ${alpha(primaryAccent, 1)} 0%, ${alpha('#5eead4', 0.95)} 100%)`
          }
        }
      }
    },
    MuiDialog: {
      styleOverrides: {
        paper: {
          borderRadius: 24,
          backgroundColor: '#0b172d',
          border: `1px solid ${alpha('#94a3c6', 0.18)}`,
          boxShadow: `0 36px 120px ${alpha('#000', 0.6)}`
        }
      }
    },
    MuiOutlinedInput: {
      styleOverrides: {
        root: {
          '& .MuiOutlinedInput-notchedOutline': {
            borderColor: alpha('#60a5fa', 0.35)
          },
          '&:hover .MuiOutlinedInput-notchedOutline': {
            borderColor: alpha('#60a5fa', 0.65)
          },
          '&.Mui-focused .MuiOutlinedInput-notchedOutline': {
            borderColor: primaryAccent,
            boxShadow: `0 0 0 4px ${alpha(primaryAccent, 0.15)}`
          }
        },
        input: {
          paddingTop: '0.9rem',
          paddingBottom: '0.9rem'
        }
      }
    },
    MuiInputLabel: {
      styleOverrides: {
        root: {
          color: alpha('#cbd5f5', 0.78),
          '&.Mui-focused': {
            color: primaryAccent
          }
        }
      }
    },
    MuiMenu: {
      styleOverrides: {
        paper: {
          borderRadius: 18,
          border: `1px solid ${alpha('#93c5fd', 0.24)}`,
          backgroundColor: '#0b1424',
          boxShadow: `0 28px 80px ${alpha('#000', 0.45)}`
        }
      }
    },
    MuiTooltip: {
      styleOverrides: {
        tooltip: {
          borderRadius: 12,
          backgroundColor: alpha('#0f172a', 0.92),
          border: `1px solid ${alpha('#94a3c6', 0.24)}`
        }
      }
    }
  }
})

const vaultTheme = responsiveFontSizes(rawTheme)

export default vaultTheme
