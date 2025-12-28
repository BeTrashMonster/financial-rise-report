# Privacy Policy Update - Right to Object (GDPR Article 21)

## Section to Add to Privacy Policy

The following section should be added to the Financial RISE Privacy Policy under "Your Rights Under GDPR":

---

## 5. Right to Object to Processing (Article 21)

You have the right to object to certain types of processing of your personal data. When you object, we must stop processing your data for that purpose unless we can demonstrate compelling legitimate grounds that override your interests, rights, and freedoms.

### What You Can Object To

You can object to the following types of processing:

#### Marketing Communications
You have an absolute right to object to processing for direct marketing purposes at any time. If you object, we will immediately stop sending you marketing communications. This includes:
- Promotional emails and newsletters
- Product announcements and feature updates
- Invitations to webinars and events
- Surveys about product improvements

**Note:** You will still receive transactional emails necessary for the service, such as password reset emails, assessment completion notifications, and billing statements.

#### Analytics and Statistics
You can object to the use of your data for analytics, statistics, and usage pattern analysis. If you object, we will:
- Exclude your data from aggregate statistics and reporting
- Stop tracking your usage patterns for product improvement
- Not use your data to analyze trends or user behavior

**Note:** Essential security logging and debugging will continue to protect the integrity of our service.

#### Profiling and Automated Decision-Making
You can object to automated decision-making and profiling based on your data. If you object, we will:
- Disable automated recommendations and personalized experiences
- Not use your data for predictive analytics
- Stop profiling for purposes other than the core assessment service

**Note:** The core DISC assessment and Financial RISE phase determination will continue as this is the essential purpose of the service you signed up for.

### What You CANNOT Object To

Certain processing is necessary and cannot be objected to:

1. **Processing necessary for the performance of a contract with you:**
   - Storing your assessment data
   - Generating reports you requested
   - Authenticating your account
   - Processing payments

2. **Processing necessary for compliance with a legal obligation:**
   - Tax record retention
   - Financial compliance reporting
   - Court-ordered data disclosure

3. **Processing necessary for the establishment, exercise, or defense of legal claims:**
   - Audit logs for security incidents
   - Evidence preservation for legal disputes

4. **Processing with your explicit consent:**
   - If you have provided explicit consent for processing (e.g., opting into beta features), you cannot object but you can withdraw consent at any time.

### How to Exercise Your Right to Object

You can object to processing in three ways:

#### 1. Via API (Recommended for Technical Users)
```bash
POST /api/users/{your-user-id}/object-to-processing
{
  "objection_type": "marketing",
  "reason": "I do not wish to receive promotional communications"
}
```

Valid objection types: `marketing`, `analytics`, `profiling`

#### 2. Via Account Settings (Coming Soon)
Navigate to Account Settings > Privacy > Objections and select the types of processing you wish to object to.

#### 3. Via Email
Send an email to privacy@financialrise.com with:
- Subject: "Right to Object - Article 21"
- Your registered email address
- The type(s) of processing you object to (marketing, analytics, profiling)
- A brief reason for your objection

### Processing Time

We will process your objection **immediately** (within 24 hours maximum). This is significantly faster than the one-month period allowed under GDPR.

You will receive a confirmation email once your objection has been processed.

### No Cost, No Consequences

Exercising your right to object is:
- **Free of charge:** There are no fees for objecting to processing
- **Without adverse consequences:** We will not limit your access to the service or treat you differently
- **Reversible:** You can withdraw your objection at any time

### Withdrawing an Objection

If you change your mind, you can withdraw your objection at any time using the same methods:

#### Via API
```bash
DELETE /api/users/{your-user-id}/objections/{objection-id}
```

#### Via Email
Send an email to privacy@financialrise.com requesting withdrawal of your objection.

### Viewing Your Current Objections

You can view all your active objections at any time:

#### Via API
```bash
GET /api/users/{your-user-id}/objections
```

#### Via Account Settings (Coming Soon)
Navigate to Account Settings > Privacy > Objections to view and manage your objections.

### Our Response to Your Objection

When you object to processing, we will:

1. **Acknowledge** your objection within 24 hours
2. **Stop processing** immediately for marketing objections
3. **Assess** whether we have compelling legitimate grounds to continue other types of processing
4. **Inform you** of our decision and the reasons
5. **Provide appeal options** if we decide to continue processing

### Compelling Legitimate Grounds

For objections to analytics and profiling (but not marketing), we may continue processing if we can demonstrate:

- The processing is necessary for the performance of the service
- The processing is necessary for compliance with legal obligations
- Our legitimate interests in processing override your interests, rights, and freedoms

If we rely on compelling legitimate grounds, we will:
- Explain our reasoning in detail
- Provide evidence of the legitimate grounds
- Give you the opportunity to challenge our decision
- Inform you of your right to lodge a complaint with a supervisory authority

### Record Keeping

We maintain records of all objections including:
- The date and time of the objection
- The type of processing objected to
- The reason provided
- The action taken
- Any withdrawals of objections

These records are kept for compliance and audit purposes.

### Your Other Rights

The right to object works alongside your other GDPR rights:

- **Right to Access (Article 15):** Request a copy of all your data
- **Right to Rectification (Article 16):** Correct inaccurate data
- **Right to Erasure (Article 17):** Delete your account and all data
- **Right to Restriction (Article 18):** Temporarily restrict processing
- **Right to Data Portability (Article 20):** Receive your data in a portable format

For more information about these rights, see the relevant sections of this Privacy Policy.

### Contact Information

**Data Protection Officer**
Email: dpo@financialrise.com

**Privacy Inquiries**
Email: privacy@financialrise.com

**Postal Address**
Financial RISE
ATTN: Privacy Department
[Your Company Address]

### Supervisory Authority

If you believe we have not adequately addressed your objection, you have the right to lodge a complaint with your local data protection supervisory authority.

**For users in the EU:**
Find your supervisory authority at: https://edpb.europa.eu/about-edpb/board/members_en

**For users in the UK:**
Information Commissioner's Office (ICO)
Website: https://ico.org.uk/make-a-complaint/

**For users in California:**
California Attorney General's Office
Website: https://oag.ca.gov/privacy

---

## Implementation Checklist

When adding this to your Privacy Policy:

- [ ] Add this section under "Your Rights Under GDPR"
- [ ] Update the table of contents
- [ ] Update the "Last Updated" date at the top of the policy
- [ ] Add a changelog entry noting the addition of Article 21 rights
- [ ] Send notification to all users about the privacy policy update
- [ ] Post the update on your website
- [ ] Archive the previous version of the privacy policy
- [ ] Update any privacy-related help documentation
- [ ] Train support staff on how to handle objection requests

## Notification Template

Subject: Update to Our Privacy Policy - Your Right to Object

Dear [User Name],

We have updated our Privacy Policy to provide more information about your right to object to certain types of data processing under GDPR Article 21.

**What's New:**
- Clear explanation of what you can object to (marketing, analytics, profiling)
- Easy-to-use API endpoints for managing objections
- Immediate processing of objection requests
- Transparent information about what processing cannot be objected to

**What You Can Do:**
- Object to marketing communications at any time
- Object to analytics and profiling (subject to compelling legitimate grounds)
- Withdraw objections easily if you change your mind
- View all your active objections through your account

**How to Exercise This Right:**
Visit your Account Settings or use our API endpoints. For assistance, contact privacy@financialrise.com.

The updated Privacy Policy is effective immediately and can be viewed at: https://financialrise.com/privacy

If you have any questions, please don't hesitate to reach out.

Best regards,
The Financial RISE Team

---

## Legal Review Notes

Before publishing:

1. **Have legal counsel review** this section to ensure it meets all applicable laws
2. **Verify contact information** is current and monitored
3. **Confirm supervisory authorities** listed are appropriate for your jurisdiction
4. **Test all API endpoints** mentioned in the examples
5. **Ensure consistency** with other GDPR rights sections in the privacy policy
