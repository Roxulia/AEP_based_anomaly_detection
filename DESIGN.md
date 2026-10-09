
---
---
name: Serene Professional Operational System
version: 1.1.0
description: A high-trust, professional design system for financial and operational management, characterized by tonal teal layering, crisp typography, and responsive efficiency.

## 🎨 Color Palette

### Brand Colors
| Token | Hex | Usage |
|---|---|---|
| Primary | #00677f | Main brand color, primary CTAs, and active states. |
| Secondary | #2babce | Supporting actions, accents, and visual hierarchy. |
| Tertiary | #e0f2f1 | Soft backgrounds, progress bars, and subtle highlights. |

### Surface & Neutral
| Token | Hex | Usage |
|---|---|---|
| Surface | #f6f9ff | Primary app background. |
| Surface-Dim | #c9dcf0 | Secondary backgrounds and containers. |
| Surface-Bright | #f6f9ff | Elevated surfaces and cards. |
| Container-Lowest | #ffffff | Cards, modals, and input fields. |
| Container-Low | #ecf5ff | Subtle sectional backgrounds. |
| Outline | #b0bec5 | Borders and dividers. |

### Semantic States
| State | Color | Hex |
|---|---|---|
| Success | Emerald | #10b981 |
| Warning | Amber | #f59e0b |
| Error | Rose | #ef4444 |
| Info | Sky | #0ea5e9 |

## Typography

**Primary Font:** Manrope (Headlines, CTAs)
**Secondary Font:** Inter (Body, Data, Labels)

### Type Scale
- **Headline-LG:** 32px / 40px Leading (Bold)
- **Headline-MD:** 24px / 32px Leading (Semi-Bold)
- **Headline-SM:** 20px / 28px Leading (Semi-Bold)
- **Body-LG:** 18px / 26px Leading (Regular)
- **Body-MD:** 16px / 24px Leading (Regular)
- **Label-MD:** 14px / 20px Leading (Medium/Semi-Bold)
- **Label-SM:** 12px / 16px Leading (Medium)

## 🔘 Buttons & Interactions

### Primary Button
- **Default:** `bg-[#00677f] text-white`
- **Hover:** `bg-[#005266]` (10% Darker)
- **Active:** `scale-95 bg-[#004050]`
- **Disabled:** `bg-[#b0bec5] text-[#f6f9ff] cursor-not-allowed`
- **Shape:** Round-Eight (8px)

### Secondary/Outline Button
- **Default:** `border border-[#00677f] text-[#00677f] bg-transparent`
- **Hover:** `bg-[#e0f2f1]` (Tertiary tint)
- **Active:** `bg-[#c9dcf0]`
- **Disabled:** `border-[#b0bec5] text-[#b0bec5]`

### Ghost/Text Button
- **Default:** `text-[#00677f] bg-transparent`
- **Hover:** `bg-[#ecf5ff]`
- **Active:** `bg-[#c9dcf0]`

## 📝 Form Elements

### Text Inputs & Textareas
- **Default:** `bg-white border border-[#b0bec5] rounded-lg px-4 py-2 text-body-md`
- **Focus:** `border-[#00677f] ring-2 ring-[#2babce]/20 outline-none`
- **Error:** `border-[#ef4444] text-[#ef4444]`
- **Disabled:** `bg-[#f6f9ff] border-[#c9dcf0] text-[#b0bec5]`

### Selects & Checkboxes
- **Selects:** Custom chevron-down icon in Primary color, same border logic as inputs.
- **Checkboxes:** `rounded-sm border-[#00677f] text-[#00677f] focus:ring-[#2babce]`

## 📊 Tables & Data Grids

### Desktop Table
- **Header:** `bg-[#ecf5ff] text-label-md font-bold uppercase tracking-wider py-3 px-4 border-b border-[#b0bec5]`
- **Row:** `bg-white hover:bg-[#f6f9ff] transition-colors border-b border-[#ecf5ff]`
- **Cell:** `py-4 px-4 text-body-md align-middle`
- **Empty State:** Centered illustration in tonal teal with #00677f CTA.

## 🗂️ Cards & Containers

### Data Card
- **Background:** `bg-white`
- **Elevation:** None (Border-based layering)
- **Border:** `border border-[#ecf5ff]` or tonal shadow `shadow-[0_2px_12px_rgba(0,103,127,0.05)]`
- **Radius:** 12px (Large) for major sections, 8px for nested items.

## 🏗️ Desktop Navigation

### SideNavBar
- **Width:** 256px (Fixed)
- **Background:** `bg-surface-container-low` (#ecf5ff)
- **Active State:** `bg-[#2babce]/10 text-[#00677f]` with 4px left border in `#2babce`.
- **Typography:** font-label-caps.

### TopNavBar
- **Height:** 64px
- **Features:** Global search, notifications, profile avatar, and breadcrumbs.
- **Separation:** `border-b border-[#b0bec5]`.

## 📱 Mobile Components

### TopAppBar
- **Layout:** Leading icon/brand, trailing avatar.
- **Background:** `bg-[#f6f9ff]`.
- **Separation:** Subtle shadow or `border-b border-[#ecf5ff]`.

### BottomNavBar
- **Height:** 64px
- **Items:** 4-5 core destinations.
- **Active State:** Icon and label in `#00677f`, with a subtle #2babce background pill.
- **Style:** `bg-white` with top border `border-[#ecf5ff]`.

### Mobile Cards
- **Structure:** Stacked vertically, replacing horizontal table rows.
- **Hierarchy:** High-level metrics (e.g. Total Amount) as Headline-SM, metadata as Label-SM.

## 📏 Layout & Spacing
- **Container Padding:** 16px (Mobile) / 32px (Desktop)
- **Element Gap:** 8px (Small), 16px (Medium), 24px (Large)
- **Corner Radius:** 8px (Standard), 12px (Large Cards/Modals)


## Brand & Style

This design system embodies a calm, professional, and sophisticated personality. It is tailored for high-trust environments such as SaaS, Finance, or Health platforms where clarity and reliability are paramount. The aesthetic is rooted in **Corporate / Modern** principles with a leaning toward atmospheric tonal layering. 

The emotional response should be one of stability and ease. By utilizing a monochromatic teal spectrum with a vibrant primary accent, the UI minimizes cognitive load and creates a cohesive, immersive environment that feels intentional and premium.

## Colors

The palette is derived from a sophisticated teal and blue-gray scale, now enhanced with a more luminous primary action color to improve interactive clarity.

- **Primary:** A vibrant cyan-teal (#2BABCE) serves as the core action color, used for primary buttons, active states, and critical brand touchpoints.
- **Deep Shades:** #1F5161 (Secondary) and #0B1F2D (Neutral) are reserved for headers, sidebars, and high-contrast typography to provide a strong structural anchor.
- **Surface Tints:** #B8D7DF (Tertiary) and associated lighter variants function as background and container colors, creating a "breathable" interface.
- **Functional Neutrals:** The deepest shade (#0B1F2D) serves as the primary text color to maintain high legibility against the pale teal backgrounds.

## Typography

The typography system utilizes **Manrope** for headlines to provide a modern, slightly geometric character that feels premium. **Inter** is used for body copy and labels due to its exceptional legibility and systematic, utilitarian nature.

Hierarchy is established through weight and color:
- **Headlines:** Use the deep #1F5161 to command attention.
- **Body:** Uses the neutral #0B1F2D for maximum readability.
- **Captions/Labels:** Use the vibrant primary #2BABCE to differentiate secondary information without losing the brand's color presence.

## Layout & Spacing

This design system employs a **Fluid Grid** model based on a 4px baseline unit. 

- **Desktop:** 12-column grid with 24px gutters. Content is typically centered with a maximum container width of 1280px.
- **Tablet:** 8-column grid with 24px gutters.
- **Mobile:** 4-column grid with 16px gutters and 16px side margins.

Spacing between related elements (like an icon and text) should use `sm` (8px). Spacing between distinct sections within a card should use `md` (16px), while padding for top-level containers should use `lg` (24px) or `xl` (32px).

## Elevation & Depth

Depth is achieved through **Tonal Layering** rather than heavy shadows. This reinforces the clean, professional aesthetic.

- **Level 0 (Background):** Uses the softest surface tints derived from the tertiary palette.
- **Level 1 (Cards/Containers):** Uses white (#FFFFFF) with a very subtle, diffused shadow (0px 4px 20px rgba(11, 31, 45, 0.05)).
- **Level 2 (Popovers/Modals):** Pure white backgrounds with a more defined shadow to suggest proximity to the user.
- **Interactions:** Hover states on interactive elements should shift the background color or subtly increase the shadow spread.

## Shapes

The design system uses a **Rounded** shape language to soften the professional tone and make the UI feel approachable. 

- Standard components (Buttons, Inputs) use a 0.5rem (8px) corner radius.
- Larger containers (Cards, Modals) use a 1rem (16px) corner radius.
- Small decorative elements (Chips, Tags) may use a pill-shape (full rounding) to contrast against the more structured rectangular components.

## Components

### Buttons
- **Primary:** Background #2BABCE, Text #FFFFFF. 8px corner radius.
- **Secondary:** Border 1px #2BABCE, Text #2BABCE, Background transparent.
- **Ghost:** Text #1F5161, Background transparent.

### Input Fields
- Background: #FFFFFF or light tertiary tint.
- Border: 1px #B8D7DF. On focus: 2px #2BABCE.
- Text: #0B1F2D. Placeholder: #8BAFB7.

### Cards
- Background: #FFFFFF.
- Border: None, or a very light 1px #B8D7DF for definition on light backgrounds.
- Shadow: Subtle ambient shadow as defined in the Elevation section.

### Chips & Tags
- Background: #B8D7DF.
- Text: #1F5161 (High contrast for accessibility).
- Shape: Fully rounded (pill).

### Lists
- Use subtle horizontal dividers in #B8D7DF. 
- Active list items should use a soft background tint with a 4px #2BABCE left-accent border.