// Port of go-tuf v2.4.2 metadata/trustedmetadata: the set of trusted
// metadata, updated in the order the TUF client workflow requires
// (root → timestamp → snapshot → targets) with each step's checks.

import Foundation

/// Mirrors `trustedmetadata.TrustedMetadata`.
public struct TrustedMetadata: Sendable {
    /// The trusted root.
    public private(set) var root: Metadata<RootType>
    /// The trusted snapshot, once loaded.
    public private(set) var snapshot: Metadata<SnapshotType>?
    /// The trusted timestamp, once loaded.
    public private(set) var timestamp: Metadata<TimestampType>?
    /// The trusted top-level and delegated targets, by role name.
    public private(set) var targets: [String: Metadata<TargetsType>] = [:]
    /// Reference time for expiry checks (fixed at creation, as in go-tuf).
    public var refTime: Date

    /// Mirrors `trustedmetadata.New`: loads `rootData` as the trusted root
    /// (it must be signed by its own root role).
    public init(rootData: Data, refTime: Date = Date()) throws {
        let newRoot = try Metadata<RootType>(fromBytes: rootData)
        guard newRoot.signed.type == TUFRole.root else {
            throw TUFError.repository("expected \(TUFRole.root), got \(newRoot.signed.type)")
        }
        try newRoot.verifyDelegate(TUFRole.root, newRoot)
        self.root = newRoot
        self.refTime = refTime
    }

    /// Mirrors `UpdateRoot`: the next root version must be signed by the
    /// current root's root role and by its own, with version + 1.
    @discardableResult
    public mutating func updateRoot(_ rootData: Data) throws -> Metadata<RootType> {
        guard timestamp == nil else { throw TUFError.runtime("cannot update root after timestamp") }
        let newRoot = try Metadata<RootType>(fromBytes: rootData)
        guard newRoot.signed.type == TUFRole.root else {
            throw TUFError.repository("expected \(TUFRole.root), got \(newRoot.signed.type)")
        }
        try root.verifyDelegate(TUFRole.root, newRoot)
        guard newRoot.signed.version == root.signed.version + 1 else {
            throw TUFError.badVersionNumber(
                "bad version number, expected \(root.signed.version + 1), got \(newRoot.signed.version)")
        }
        try newRoot.verifyDelegate(TUFRole.root, newRoot)
        root = newRoot
        return newRoot
    }

    /// Mirrors `UpdateTimestamp`.
    @discardableResult
    public mutating func updateTimestamp(_ data: Data) throws -> Metadata<TimestampType> {
        guard snapshot == nil else { throw TUFError.runtime("cannot update timestamp after snapshot") }
        if root.signed.isExpired(refTime) { throw TUFError.expiredMetadata("final root.json is expired") }
        let newTimestamp = try Metadata<TimestampType>(fromBytes: data)
        guard newTimestamp.signed.type == TUFRole.timestamp else {
            throw TUFError.repository("expected \(TUFRole.timestamp), got \(newTimestamp.signed.type)")
        }
        try root.verifyDelegate(TUFRole.timestamp, newTimestamp)
        if let current = timestamp {
            if newTimestamp.signed.version < current.signed.version {
                throw TUFError.badVersionNumber(
                    "new timestamp version \(newTimestamp.signed.version) must be >= \(current.signed.version)")
            }
            if newTimestamp.signed.version == current.signed.version {
                throw TUFError.equalVersionNumber(
                    "new timestamp version \(newTimestamp.signed.version) equals the old one \(current.signed.version)")
            }
            let old = current.signed.meta["snapshot.json"]?.version ?? 0
            let new = newTimestamp.signed.meta["snapshot.json"]?.version ?? 0
            if new < old {
                throw TUFError.badVersionNumber("new snapshot version \(new) must be >= \(old)")
            }
        }
        timestamp = newTimestamp
        try checkFinalTimestamp()
        return newTimestamp
    }

    private func checkFinalTimestamp() throws {
        if timestamp!.signed.isExpired(refTime) { throw TUFError.expiredMetadata("timestamp.json is expired") }
    }

    /// Mirrors `UpdateSnapshot`. `isTrusted` skips the length/hash check
    /// against timestamp's meta (for locally cached snapshots).
    @discardableResult
    public mutating func updateSnapshot(_ data: Data, isTrusted: Bool) throws -> Metadata<SnapshotType> {
        guard let timestamp else { throw TUFError.runtime("cannot update snapshot before timestamp") }
        guard targets[TUFRole.targets] == nil else { throw TUFError.runtime("cannot update snapshot after targets") }
        try checkFinalTimestamp()
        // Go dereferences this unconditionally (a nil map entry panics).
        guard let snapshotMeta = timestamp.signed.meta["snapshot.json"] else {
            throw TUFError.repository("timestamp does not contain snapshot.json meta")
        }
        if !isTrusted { try snapshotMeta.verifyLengthHashes(data) }
        let newSnapshot = try Metadata<SnapshotType>(fromBytes: data)
        guard newSnapshot.signed.type == TUFRole.snapshot else {
            throw TUFError.repository("expected \(TUFRole.snapshot), got \(newSnapshot.signed.type)")
        }
        try root.verifyDelegate(TUFRole.snapshot, newSnapshot)
        if let current = snapshot {
            for (name, info) in current.signed.meta {
                guard let newInfo = newSnapshot.signed.meta[name] else {
                    throw TUFError.repository("new snapshot is missing info for \(name)")
                }
                if newInfo.version < info.version {
                    throw TUFError.badVersionNumber("expected \(name) version \(newInfo.version), got \(info.version)")
                }
            }
        }
        snapshot = newSnapshot
        try checkFinalSnapshot()
        return newSnapshot
    }

    private func checkFinalSnapshot() throws {
        guard let snapshot, let timestamp else { return }
        if snapshot.signed.isExpired(refTime) { throw TUFError.expiredMetadata("snapshot.json is expired") }
        let expected = timestamp.signed.meta["snapshot.json"]?.version ?? 0
        if snapshot.signed.version != expected {
            throw TUFError.badVersionNumber("expected \(expected), got \(snapshot.signed.version)")
        }
    }

    /// Mirrors `UpdateTargets`.
    @discardableResult
    public mutating func updateTargets(_ data: Data) throws -> Metadata<TargetsType> {
        try updateDelegatedTargets(data, roleName: TUFRole.targets, delegatorName: TUFRole.root)
    }

    /// Mirrors `UpdateDelegatedTargets`.
    @discardableResult
    public mutating func updateDelegatedTargets(_ data: Data, roleName: String, delegatorName: String) throws
        -> Metadata<TargetsType>
    {
        guard let snapshot else { throw TUFError.runtime("cannot load targets before snapshot") }
        try checkFinalSnapshot()
        guard delegatorName == TUFRole.root || targets[delegatorName] != nil else {
            throw TUFError.runtime("cannot load targets before delegator")
        }
        guard let meta = snapshot.signed.meta["\(roleName).json"] else {
            throw TUFError.repository("snapshot does not contain information for \(roleName)")
        }
        try meta.verifyLengthHashes(data)
        let newDelegate = try Metadata<TargetsType>(fromBytes: data)
        guard newDelegate.signed.type == TUFRole.targets else {
            throw TUFError.repository("expected \(TUFRole.targets), got \(newDelegate.signed.type)")
        }
        if delegatorName == TUFRole.root {
            try root.verifyDelegate(roleName, newDelegate)
        } else {
            try targets[delegatorName]!.verifyDelegate(roleName, newDelegate)
        }
        if newDelegate.signed.version != meta.version {
            throw TUFError.badVersionNumber(
                "expected \(roleName) version \(meta.version), got \(newDelegate.signed.version)")
        }
        if newDelegate.signed.isExpired(refTime) { throw TUFError.expiredMetadata("new \(roleName) is expired") }
        targets[roleName] = newDelegate
        return newDelegate
    }
}
