# How to Run Tests - Quick Reference

## ✅ Verification (No Servers Needed)

Test that Playwright is working:

```bash
cd financial-rise-app/e2e
SKIP_WEBSERVER=true npx playwright test smoke.spec.ts --project=chromium
```

**Result:** Should show "6 passed"

---

## 🚀 Full Test Suite

### Option 1: With Servers Already Running (Recommended)

**Step 1 - Start Servers (in separate terminals):**

```bash
# Terminal 1 - Backend
cd financial-rise-app/backend
npm run start:dev

# Terminal 2 - Frontend
cd financial-rise-app/frontend
npm run dev

# Terminal 3 - Tests
cd financial-rise-app/e2e
SKIP_WEBSERVER=true npm test
```

### Option 2: Auto-Start Servers

Let Playwright start the servers automatically:

```bash
cd financial-rise-app/e2e
npm test
```

> **Note:** This may take 2+ minutes as it builds and starts both servers

---

## 🎨 Interactive UI Mode (Best for Development)

```bash
cd financial-rise-app/e2e
npm run test:ui
```

This opens a GUI where you can:
- Run individual tests
- Watch tests in slow motion
- Time-travel debug with trace viewer
- See live browser preview
- Pick & test locators

---

## 🐛 Debug Mode

```bash
cd financial-rise-app/e2e
npm run test:debug
```

Opens Playwright Inspector to step through tests.

---

## 📊 View Test Reports

```bash
cd financial-rise-app/e2e
npm run report
```

Opens HTML report at http://localhost:9323

---

## 🎯 Run Specific Tests

```bash
# Single file
npx playwright test auth.spec.ts

# Single test
npx playwright test -g "should display login form"

# Specific browser
npm run test:chromium
npm run test:firefox
npm run test:webkit

# Mobile
npm run test:mobile

# Headed mode (see browser)
npm run test:headed
```

---

## 📝 Generate Tests

Record your actions to generate test code:

```bash
npm run codegen http://localhost:5173
```

Interact with your app, Playwright writes the code!

---

## 🔧 Environment Setup

Create `.env` file:

```bash
cp .env.example .env
```

Edit `.env`:

```env
BASE_URL=http://localhost:5173
API_BASE_URL=http://localhost:3000
TEST_USER_EMAIL=your-test-user@example.com
TEST_USER_PASSWORD=your-password
```

---

## 📁 Where to Find Things

- **Test files:** `tests/*.spec.ts`
- **Helpers:** `tests/helpers/`
- **Config:** `playwright.config.ts`
- **Screenshots/Videos:** `test-results/`
- **HTML Report:** `playwright-report/`

---

## 💡 Pro Tips

1. **Use UI Mode** - Best for writing and debugging tests
2. **Add data-testid** - More stable selectors than text/classes
3. **Use helpers** - Import from `tests/helpers/fixtures.ts`
4. **Debug with pause** - Add `await page.pause()` to stop execution
5. **Check artifacts** - Screenshots and videos saved on failure

---

## ❓ Troubleshooting

**Tests timeout:**
- Check if servers are running
- Check `playwright.config.ts` timeout settings
- Look for slow network requests

**Can't find elements:**
- Use `npx playwright codegen` to find selectors
- Check if element is in iframe or shadow DOM
- Verify element is visible (not hidden by CSS)

**Connection refused:**
- Make sure backend (port 3000) and frontend (port 5173) are running
- Check if ports are already in use

**Authentication errors:**
- Create test user in database
- Update credentials in `.env`
- Delete `tests/.auth/` and regenerate

---

## 🎓 Learn More

- [Playwright Docs](https://playwright.dev)
- [Best Practices](https://playwright.dev/docs/best-practices)
- [API Reference](https://playwright.dev/docs/api/class-test)
- See `README.md` for detailed documentation
