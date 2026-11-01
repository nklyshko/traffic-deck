import hooks from 'eslint-plugin-react-hooks'
import ts from 'typescript-eslint'

export default ts.config(...ts.configs.recommended, {
  plugins: { 'react-hooks': hooks },
  rules: {
    'react-hooks/rules-of-hooks': 'error',
    'react-hooks/exhaustive-deps': 'warn',
    '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
  },
})
