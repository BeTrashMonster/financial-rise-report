# CCPA "Do Not Sell My Personal Information" Implementation

## Overview

This document describes the implementation of the CCPA "Do Not Sell My Personal Information" notice for the Financial RISE Report application, as required by the California Consumer Privacy Act (CCPA) § 1798.135.

**Implementation Date:** December 28, 2025
**Work Stream:** 66 - GDPR/CCPA Compliance
**Priority:** HIGH (Required before production)

## Requirements Met

### CCPA § 1798.135 Compliance

The CCPA requires businesses to provide a clear and conspicuous link titled "Do Not Sell My Personal Information" on their website homepage and in their privacy policy, even if the business does not actually sell personal information.

Our implementation satisfies this requirement by:

1. **Prominent Footer Link** - The link appears in every page footer with:
   - Clear, descriptive text: "Do Not Sell My Personal Information"
   - Visual prominence (primary color, bold weight, security icon)
   - Mobile-responsive design
   - Accessible placement

2. **Dedicated CCPA Disclosure Page** - Comprehensive page explaining:
   - That we DO NOT sell personal information
   - CCPA rights for California residents
   - How to exercise privacy rights
   - Contact information for privacy inquiries

3. **Privacy Policy Integration** - The Privacy Policy includes:
   - Section 7.2 dedicated to CCPA rights
   - Explicit statement that data is not sold
   - Link to the Do Not Sell page
   - Full disclosure of data collection and usage

## Files Modified/Created

### Modified Files

1. **`src/components/layout/Footer/Footer.tsx`**
   - Added CCPA "Do Not Sell" link with GppGood icon
   - Styled for prominence (primary color, bold weight)
   - Mobile-responsive layout

2. **`src/routes/index.tsx`**
   - Added public routes for `/privacy` and `/do-not-sell`
   - Routes are accessible without authentication

### New Files Created

1. **`src/pages/DoNotSell/DoNotSell.tsx`**
   - Dedicated CCPA disclosure page
   - Explains that we do NOT sell data
   - Lists all CCPA rights
   - Provides contact information
   - Links to Privacy Policy

2. **`src/pages/Privacy/Privacy.tsx`**
   - Comprehensive Privacy Policy
   - GDPR compliance (Section 7.1)
   - CCPA compliance (Section 7.2)
   - Full data collection and usage disclosure
   - Security measures explained
   - Contact information

3. **Test Files:**
   - `src/components/layout/Footer/Footer.test.tsx`
   - `src/pages/DoNotSell/DoNotSell.test.tsx`
   - `src/pages/Privacy/Privacy.test.tsx`

## Component Structure

### Footer Component

```tsx
// CCPA Notice appears in footer with:
<Box sx={{ display: 'flex', gap: 0.5, alignItems: 'center' }}>
  <GppGoodIcon sx={{ fontSize: 16, color: 'primary.main' }} />
  <Link
    href="/do-not-sell"
    color="primary"
    variant="body2"
    sx={{ fontWeight: 600 }}
  >
    Do Not Sell My Personal Information
  </Link>
</Box>
```

### DoNotSell Page Features

- **Clear Notice:** Large, prominent statement that data is NOT sold
- **CCPA Rights:** Complete list of California consumer rights
- **Contact Info:** Email and phone for privacy inquiries
- **Privacy Policy Link:** Direct link to full policy
- **Responsive Design:** Works on mobile and desktop
- **Accessible:** Proper ARIA labels and semantic HTML

### Privacy Policy Page Features

- **12 Comprehensive Sections:**
  1. Introduction
  2. Information We Collect
  3. How We Use Your Information
  4. Information Sharing and Disclosure
  5. Data Security
  6. Data Retention
  7. Your Privacy Rights (GDPR & CCPA)
  8. Cookies and Tracking
  9. Third-Party Links
  10. Children's Privacy
  11. Changes to Policy
  12. Contact Information

- **CCPA Section 7.2:** Dedicated California rights section
- **Prominent "Do Not Sell" Notice:** Highlighted box linking to /do-not-sell
- **Legal Compliance:** Covers GDPR, CCPA, and other privacy laws

## Styling and User Experience

### Visual Prominence

The CCPA link in the footer:
- Uses **primary brand color** (purple #4B006E per REQ-UI-002)
- Has **bold font weight** (600)
- Includes a **security shield icon** (GppGoodIcon)
- Appears **on a separate line** from other footer links
- Includes **hover effects** for better UX

### Mobile Responsiveness

All pages and the footer adapt to mobile screens:
- Footer links stack vertically on mobile
- Page content uses responsive containers
- Text remains readable at all screen sizes
- Touch targets meet accessibility guidelines

### Accessibility

- Proper semantic HTML (`<footer>`, `<nav>`, heading hierarchy)
- ARIA roles (`role="contentinfo"`)
- Sufficient color contrast
- Keyboard navigable
- Screen reader friendly

## Compliance Checklist

- [x] "Do Not Sell" link on all pages (via footer)
- [x] Link uses exact or substantially similar language
- [x] Link is clearly and conspicuously displayed
- [x] Link directs to opt-out mechanism or disclosure
- [x] Disclosure states whether business sells data
- [x] Disclosure explains CCPA rights
- [x] Contact information provided for privacy requests
- [x] Privacy Policy includes CCPA section
- [x] Mobile-responsive implementation
- [x] Accessible to users with disabilities

## Testing

### Manual Testing Checklist

1. **Footer Visibility:**
   - [ ] CCPA link appears on all pages
   - [ ] Link is visually prominent (not buried)
   - [ ] Icon displays correctly
   - [ ] Link text is readable

2. **Navigation:**
   - [ ] Clicking link goes to `/do-not-sell`
   - [ ] Page loads without errors
   - [ ] Privacy Policy link works
   - [ ] Back button returns to previous page

3. **Mobile Testing:**
   - [ ] Footer stacks properly on mobile
   - [ ] Text is readable on small screens
   - [ ] Links are tappable (sufficient spacing)
   - [ ] Pages scroll smoothly

4. **Content Verification:**
   - [ ] DoNotSell page states we DON'T sell data
   - [ ] All CCPA rights are listed
   - [ ] Contact information is correct
   - [ ] Privacy Policy links to /do-not-sell

### Automated Tests

Run the test suite:

```bash
npm test
```

Tests cover:
- Footer component rendering
- CCPA link presence and attributes
- DoNotSell page content
- Privacy Policy page sections
- Link navigation
- Accessibility attributes

## Contact Information

**Update Required:** The following placeholder contact information must be updated before production:

- **Email:** privacy@financialrise.com (verify this is correct)
- **Phone:** 1-800-XXX-XXXX (add real privacy hotline)
- **Address:** [Company Address] (add physical address)

## Next Steps

1. **Legal Review:** Have legal counsel review the Privacy Policy and CCPA disclosure
2. **Update Contact Info:** Replace placeholder phone/address with real information
3. **Final Testing:** Test on all browsers and devices
4. **Documentation:** Update any internal compliance documentation
5. **Training:** Ensure support team knows how to handle privacy requests

## References

- **CCPA § 1798.135:** Right to Opt-Out of Sale of Personal Information
- **Work Stream 66:** GDPR/CCPA Compliance (plans/roadmap.md)
- **REQ-PRIVACY-001-005:** Privacy requirements (plans/requirements.md)
- **REQ-UI-002:** Brand colors specification

## Maintenance

This CCPA notice should be reviewed:
- Annually for compliance updates
- When privacy laws change
- When data practices change
- Before any business sale or merger

Last Updated: December 28, 2025
