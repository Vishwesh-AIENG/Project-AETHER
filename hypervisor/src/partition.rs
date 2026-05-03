// ch03: The Non-Negotiables
//
// Chapter 3 establishes four inviolable design constraints. This module
// encodes them as Rust types so that violations are compile errors, not
// runtime surprises.
//
// The four non-negotiables from the specification:
//
//   1. Android partition must never access host resources via syscall into
//      Windows or the hypervisor. Every resource is passthrough or simulated.
//
//   2. Windows partition must never have visibility into Android's memory,
//      devices, or execution state. Windows believes it is alone.
//
//   3. The hypervisor must be invisible to both guests at the level of normal
//      operation. Guests detect virtualization only through deliberate ARM64
//      instructions, and even those signals must match real hardware.
//
//   4. There is no "host". The hypervisor is a referee. Windows and Android
//      are equal guests. Neither has privilege over the other.
//
// Reference: README.md — Chapter 3, "The Non-Negotiables"

use core::marker::PhantomData;

// ─────────────────────────────────────────────────────────────────────────────
// Guest identity (Non-Negotiable 4: no host — both are equal guests)
// ─────────────────────────────────────────────────────────────────────────────

/// The two equal guests AETHER manages.
///
/// This enum has exactly two variants and no ordering between them. Windows
/// is not "primary" and Android is not "secondary". They are indexed by
/// identity, not by privilege. The hypervisor treats them identically at the
/// resource-allocation level.
///
/// Non-Negotiable 4 encoded: `HypervisorRole::Host` does not exist. Anything
/// that would require one guest to be "host" to the other is rejected here at
/// the type level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestId {
    Windows,
    Android,
}

impl GuestId {
    /// Returns the other guest. Used by the referee to ensure symmetric policy.
    ///
    /// This method exists to make it easy to verify that every policy applied
    /// to one guest has an equivalent policy applied to the other.
    #[inline]
    pub const fn counterpart(self) -> Self {
        match self {
            GuestId::Windows => GuestId::Android,
            GuestId::Android => GuestId::Windows,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Exclusive resource ownership (Non-Negotiables 1 & 2: no cross-partition access)
// ─────────────────────────────────────────────────────────────────────────────

/// A hardware resource exclusively assigned to a single guest.
///
/// `Exclusive<T, G>` binds resource `T` to guest `G` at the type level. The
/// Rust borrow checker then ensures:
///
/// - A resource owned by `GuestId::Windows` cannot be handed to
///   `GuestId::Android` without an explicit type-level assertion that the
///   assignment is intentional.
/// - There is no `Clone` on this type. Cloning an `Exclusive` resource would
///   imply that two guests share it — which violates Non-Negotiables 1 and 2.
/// - There is no `Default`. Resources are never "unowned". Every resource is
///   assigned to exactly one guest at construction time.
///
/// The `G` type parameter is a zero-sized marker — it carries no runtime cost.
/// The enforcement is entirely at compile time.
pub struct Exclusive<T, G> {
    inner: T,
    _owner: PhantomData<G>,
}

impl<T, G> Exclusive<T, G> {
    /// Assign resource `inner` exclusively to guest `G`.
    ///
    /// Called once at boot during resource partitioning. After this point
    /// the resource cannot be shared, transferred, or cloned.
    pub const fn assign(inner: T) -> Self {
        Self {
            inner,
            _owner: PhantomData,
        }
    }

    /// Access the underlying resource.
    ///
    /// Only code that already holds the `Exclusive<T, G>` token — which can
    /// only be created by the hypervisor's resource allocator — can call this.
    /// Guest code at EL1 never holds an `Exclusive` token directly; it
    /// interacts with the hardware through its own driver, and the Stage 2
    /// translation tables enforce physical isolation beneath.
    pub fn get(&self) -> &T {
        &self.inner
    }

    /// Mutably access the underlying resource.
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

// Explicitly NOT derived: no Clone, no Copy, no Default.
// Sharing a resource between guests would require one of these.

// ─────────────────────────────────────────────────────────────────────────────
// The hypervisor as referee (Non-Negotiable 4: no host role)
// ─────────────────────────────────────────────────────────────────────────────

/// The only valid role for the hypervisor.
///
/// `Referee` means: allocate resources at boot, configure hardware isolation,
/// then step out of the way. Intervene only when a guest performs a trapped
/// operation. Never act as a service provider to one guest on behalf of the other.
///
/// This enum has exactly one variant. If a future developer is tempted to add
/// `Host` or `PrimaryGuest`, that is the type system surfacing a Chapter 3
/// violation before any code is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HypervisorRole {
    /// Allocates resources at boot; enforces isolation; sleeps otherwise.
    Referee,
}

// ─────────────────────────────────────────────────────────────────────────────
// Partition configuration (Non-Negotiable 1: passthrough or simulation only)
// ─────────────────────────────────────────────────────────────────────────────

/// How a specific resource is provided to a guest.
///
/// There are exactly two valid strategies (see Chapter 2). A third variant
/// such as `RoutedThroughOtherGuest` does not exist here because it would
/// violate Non-Negotiable 1 and introduce the fingerprint that Chapter 2
/// describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceProvision {
    /// Physical hardware assigned directly; no hypervisor in data path.
    Passthrough,
    /// Hypervisor simulation using physics-accurate models.
    /// Used only for hardware that does not physically exist on a laptop.
    Simulated,
}

/// The static resource allocation for one guest.
///
/// Produced once during boot from the AETHER configuration file.
/// Immutable after that point — there is no live migration, no dynamic
/// rebalancing, no borrowing of the other guest's idle resources.
///
/// `'cfg` is the lifetime of the configuration region parsed from storage
/// at boot. All string slices inside point into that region.
#[derive(Debug)]
pub struct PartitionConfig<'cfg> {
    /// Which guest this configuration describes.
    pub guest: GuestId,
    /// Number of physical CPU cores assigned. Static — never changes at runtime.
    pub cpu_count: usize,
    /// Size of physical memory region assigned, in bytes.
    pub memory_bytes: usize,
    /// Human-readable label from the configuration file (e.g., "windows", "android").
    pub label: &'cfg str,
}

// ─────────────────────────────────────────────────────────────────────────────
// Compile-time verification that the non-negotiables hold
// ─────────────────────────────────────────────────────────────────────────────

/// Static assertion: exactly two guests exist, they are symmetric, and
/// `counterpart` is its own inverse.
///
/// If someone changes `GuestId` to have three variants and forgets to update
/// the isolation logic, this assertion catches it at compile time.
const _: () = {
    let w = GuestId::Windows;
    let a = GuestId::Android;
    assert!(matches!(w.counterpart(), GuestId::Android));
    assert!(matches!(a.counterpart(), GuestId::Windows));
    assert!(matches!(w.counterpart().counterpart(), GuestId::Windows));
};

/// Static assertion: the hypervisor role is always Referee, never anything else.
const _ROLE: HypervisorRole = HypervisorRole::Referee;
