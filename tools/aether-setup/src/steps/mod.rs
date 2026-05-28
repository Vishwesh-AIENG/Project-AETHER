// Step routing. Each Step variant maps to a renderer in its own file. The
// app holds one Step value at a time and asks the right module to draw it;
// transitions go through SetupApp::go_next / SetupApp::go_back.

pub mod compat;
pub mod confirm;
pub mod disk;
pub mod done;
pub mod eula;
pub mod progress;
pub mod welcome;
pub mod wizard;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Step {
    Welcome,
    Eula,
    Compat,
    Disk,
    Wizard,
    Confirm,
    Progress,
    Done,
}

impl Step {
    pub fn title(self) -> &'static str {
        match self {
            Step::Welcome  => "Welcome",
            Step::Eula     => "License",
            Step::Compat   => "Compatibility",
            Step::Disk     => "Target Disk",
            Step::Wizard   => "First-Boot Preferences",
            Step::Confirm  => "Review",
            Step::Progress => "Installing",
            Step::Done     => "Finished",
        }
    }

    pub fn ordinal(self) -> usize {
        match self {
            Step::Welcome  => 1,
            Step::Eula     => 2,
            Step::Compat   => 3,
            Step::Disk     => 4,
            Step::Wizard   => 5,
            Step::Confirm  => 6,
            Step::Progress => 7,
            Step::Done     => 8,
        }
    }

    pub fn total() -> usize { 8 }
}
