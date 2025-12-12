---
weight: 22
title: Adaptiv Development
bookToC: true
---


# Adaptiv Development - Step by Step

## Requirements Gathering

-	Daniel, after receiving feature requests from Dave, Chris, and others, compiles a list of new features which we would like to implement soon, which therefore need requirements documents
-	Chris, Dave, and Tyler (the "requirement writers") write out requirements documents, and email them to us. Every feature should have a document-- if it's already extremely clear, the document can just be shorter (there should still be one)
-	We post the requirements documents to a shared folder within SharePoint, specifically a subfolder in Adaptiv > Documents > User Group
-   [Requrements Documents](https://tescotheeasternspecialty.SharePoint.com/sites/TESCONighthawk/Shared%20Documents/Forms/AllItems.aspx?id=%2Fsites%2FTESCONighthawk%2FShared%20Documents%2FUsers%20Group&viewid=6e9699bd%2D8209%2D436c%2D8623%2D1f447fa07fd6&newTargetListUrl=%2Fsites%2FTESCONighthawk%2FShared%20Documents&viewpath=%2Fsites%2FTESCONighthawk%2FShared%20Documents%2FForms%2FAllItems%2Easpx) can be found here. 
-	The team reads the documents
-	The team and requirements writers are free to collectively edit those documents in SharePoint if any scope changes
-	Based on our understanding so far of the feature, Daniel and the team collectively decide on "tentative assignees": the people who will probably work on each item, but not for certain yet
-	Daniel schedules a "requirements session", in which the team, and requirement writers, will meet
-	Before the requirements session, the tentative assignee creates a work item on the task board (in Azure Dev Ops) for the item
-	The work item should be in the correct sprint, or have child tasks assigned to multiple sprints. The tentative assignee should ensure this
-	The work item should have a link to the original requirement which is in SharePoint. The tentative assignee should ensure this. Don't attach a copy of the requirements document instead, because if updates are made to the document it's easier to manage those updates in SharePoint
-	The work item's description should have the requirements pasted into it, from the document, to use as a starting point for the task description (meaning, that notes / comments / corrections can be added later to the description)

## Requirements Review

-	Before the requirements session, the tentative assignee, but also potentially other team members, thinks up questions about the requirements (to clear up any ambiguities). These should be recorded in the work item somewhere, so that if the team member for some reason ends up being unable to attend the requirements session, someone else can find their questions and ask them there
-	At the requirements session, the tentative assignee (and anyone else who thought up questions) asks their questions to the requirement writers, and writes down the answers to those questions
-	At the requirements session or after it, the requirement writers present us with a ranked list of "customer priority", ranking the user's group items by customer revenue impact (retaining important customers, expected sales, etc)
-	Immediately after the requirements session, so that the answers are still refresh in their mind (but not during the meeting, to save meeting time), the tentative assignee then updates the work item description, adding those questions and answers at the bottom to clear up ambiguity. It's up to the team to do this, because the requirement writers are not in charge of our task board, and shouldn't have to do any more additional writing themselves. The tentative assignee can also add those same updates to the bottom of the requirements document in SharePoint, in a separate clarifications section like an addendum, to show that a developer wrote it as an addition. The requirements writer need to sign off on these changes though, whether the change was only made in the work item or made in both locations. This is because we need a paper trail of evidence that all parties agreed on these wording changes (showing that everyone was on the same page). The sign-off can be by email: the tentative assignee can share a link in the email with the requirements writer, with that link being to either the work item (assuming the requirement writers have access to it), or to the original document in SharePoint if the updates are also in the bottom of it
-	If there was not sufficient time for all the questions to be asked in the requirements session, we can have a second session. But if developers continue to think up questions after that, they should meet with the requirement writers separately, so as not to take up unnecessary amounts of the whole team's time
-	Now that the work item is fully understood, the tentative assignee, but also potentially other team members, comes up with an hours/days estimate, and shares that with Daniel / with the team

## Requirements Resource Allocation and Timelines

-	Now that the work item is fully understood, the tentative assignee adds technical / software-specific details into the work item, in case someone else ends up working on it. Don’t add more detail than is necessary, as this is just for facilitating the work effort, it’s not intended to be a library for future developers to read (that’s what code documentation is instead for)
-	Now that the work item is fully understood, the tentative assignee, but also potentially other team members, considers potential side effects, and informs the team, and requirement writers, of them
-	Once conversation regarding potential side effects completes, the tentative assignee updates the work item with any needed commentary about this
-	Once consensus has been reached within the team regarding the hours/days estimates, Daniel potentially reassigns some of the items to ensure that no one person's schedule is overloaded. There are now simply "assignees" / "developers", rather than "tentative assignees"
-	Now that both "customer priority" and hour estimates are known, Daniel comes up with a ranked list of final "priority" for the items, which is based on both of those things (since impact of delivery, and ease of delivery, both matter toward this)
-	QA will decide upon a "code cutoff": the length of time before the users group scheduled date, by which further code changes will be discouraged or banned, to ensure that there is enough time to finish the QA effort. QA will inform the team of this
-	Based on the priority list, the code cutoff date, and the time estimates, Daniel determines, in conjunction with the team, which items are expected to be completed by the users group meeting, which are in question, and which are out of scope. These form tiers within the priority list

## Development

-	The developers start working on the features, by creating feature branches based on master (or whatever the minimal required branch is. This ensures that each feature branch is independent and most easily able to be integrated without relying unnecessarily on other incomplete features). The features should begin with the highest-priority one assigned to that developer, to ensure completion of the most important ones
-	Daniel will send out periodic update emails on the progress of the items, all ranked by priority or at least sorted into the expectation tiers. The items may shift between tiers if unknown roadblocks arise, but this is to be avoided.
-	Daniel will also send out periodic update emails on where the team is in the process shown in this document: which steps in this document are complete, which in progress, and which are still yet to be done.
-	Periodically (roughly every two weeks), the team will collectively demo what we have so far to the requirement writers. Daniel will schedule these "periodic demos". These do not have to be done on the Demo environment, as it may be easiest for individual developers to simply share their local screens
-	Daniel and the team will record which items were internally demoed so far, and any open questions that come up during the internal demos, so make sure that each subsequent internal demo addresses those questions and doesn't redundantly demo the same things
-	When each feature is code-complete and tested by the developer, they will open a pull request into the relevant "Dev" branch of code (usually only applicable to C# repositories which can be deployed independently, not shared libraries nor non-C# code)
-	When the pull request has been code reviewed and completed, the developer then ensures that the Dev branch is deployed to the Dev environment
-	The developer can then do further testing in the Dev environment, in conjunction with the other recent features already in that branch

## Quality Assurance (QA)

-	When QA is ready to test the feature, and the developer feels it's ready for to QA, he or she will coordinate with QA to decide when to give the feature to QA
-	The developer gives the feature to QA by merging their branch directly into the relevant "release" branch (there should be a release branch for the upcoming user's group, at least if the code is in a C# repository), and then immediately ensuring that the newly updated release branch is [re]-deployed to the QA environment
-	The code cutoff is reached, and incomplete features are either locked out or discouraged from completion, unless they're almost complete (there is some leeway)
-	The developer completes a few bullet-point paragraph describing their feature, and takes some relevant screenshots, to use in a slide deck presentation to the customer's at the user group demo
-	QA completes, on the release branch
-	We ensure that the Demo environment is properly set up for the users group meeting, with the release branch deployed there and working properly along with any other environment changes needed (e.g. database changes)
-	We make the slideshow deck to present at the users group, which outlines all of our features, plus next steps. Each developer works on a slide for each of their features, with each feature slide including at least one screenshot. The rest of the slideshow deck Daniel is responsible for the majority of.

## Demo and Staff Training

-	We determine who (a requirements writer, a developer, or a manager) is going to demo each feature during the users group, and whether it's going to be a live demo or just a discussion of the slide or mockup screenshare
-	A final internal demo is performed by the team, using the Demo environment, with the release branch now deployed to that environment. During the final internal demo, the developers don't necessarily all demo their own features, because this one is supposed to be a trial run for the users group demo, so whoever is demoing each feature at the users group should present it during this final internal demo
-	We merge the changes into the master branch and deploy it to production: often this can be done even before the users group demo, so that we can tell the users at the meeting that these changes are truly done and released already
-	We hold the users group demo, either in the production environment if the changes are already live, in the Demo environment if some are not yet live (e.g. due to the code cutoff), or in multiple environments


## Release

-   Product/feature is approved by Daniel and authorized for production deployment
-   Production push is scheduled. If downtime is required. Customer service notifies customer
