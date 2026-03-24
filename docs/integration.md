---
name: wp-module-secure-passwords
title: Integration
description: How the module registers and integrates.
updated: 2025-03-18
---

# Integration

The module registers with the Newfold Module Loader via bootstrap.php. The host plugin loads it to enable breach-check and password hygiene; the module hooks into WordPress user/password validation.
