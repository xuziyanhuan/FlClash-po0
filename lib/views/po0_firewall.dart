import 'dart:async';

import 'package:fl_clash/common/common.dart';
import 'package:fl_clash/models/models.dart';
import 'package:fl_clash/providers/config.dart';
import 'package:fl_clash/providers/po0_firewall.dart';
import 'package:fl_clash/ui/icons/icons.dart';
import 'package:fl_clash/widgets/widgets.dart';
import 'package:material_ui/material_ui.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

class Po0FirewallView extends ConsumerWidget {
  const Po0FirewallView({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final appLocalizations = context.appLocalizations;
    final setting = ref.watch(po0FirewallSettingProvider);
    final isRunning = ref.watch(
      po0FirewallProvider.select((state) => state.isRunning),
    );
    final canRun =
        setting.enable && po0TokensOf(setting.tokenEntries).isNotEmpty;
    final notifier = ref.read(po0FirewallProvider.notifier);
    return CommonScaffold(
      title: appLocalizations.po0Whitelist,
      iconActions: [
        IconButtonData(
          glyph: AppGlyphs.search,
          tooltip: appLocalizations.po0Query,
          isLoading: isRunning,
          onPressed: canRun ? () => unawaited(notifier.query()) : null,
        ),
        IconButtonData(
          glyph: AppGlyphs.refresh,
          tooltip: appLocalizations.po0WhitelistNow,
          isLoading: isRunning,
          onPressed: canRun ? () => unawaited(notifier.whitelist()) : null,
        ),
      ],
      body: Builder(
        builder: (context) => ListView(
          padding: EdgeInsets.only(
            left: 16,
            right: 16,
            top: context.appBarInset,
            bottom: 20 + BottomInsetScope.of(context),
          ),
          children: const [
            _SettingSection(),
            _TokenSection(),
            _ResultSection(),
          ],
        ),
      ),
    );
  }
}

class _SettingSection extends ConsumerWidget {
  const _SettingSection();

  void _update(
    WidgetRef ref,
    Po0FirewallProps Function(Po0FirewallProps state) builder,
  ) {
    ref.read(po0FirewallSettingProvider.notifier).update(builder);
  }

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final appLocalizations = context.appLocalizations;
    final setting = ref.watch(po0FirewallSettingProvider);
    return generateSection(
      title: appLocalizations.settings,
      items: [
        ListItem.toggle(
          leading: const GlyphIcon(AppGlyphs.verified),
          title: Text(appLocalizations.po0AutoWhitelist),
          value: setting.enable,
          onChanged: (value) =>
              _update(ref, (state) => state.copyWith(enable: value)),
        ),
        ListItem.input(
          leading: const GlyphIcon(AppGlyphs.refresh),
          title: Text(appLocalizations.po0PollInterval),
          subtitle: Text(appLocalizations.secondsCount(setting.pollSeconds)),
          dialogTitle: appLocalizations.po0PollInterval,
          value: '${setting.pollSeconds}',
          suffixText: appLocalizations.seconds,
          keyboardType: TextInputType.number,
          resetValue: '${defaultPo0FirewallProps.pollSeconds}',
          validator: (value) {
            final seconds = int.tryParse(value?.trim() ?? '');
            if (seconds == null ||
                seconds < po0PollSecondsRange.min ||
                seconds > po0PollSecondsRange.max) {
              return appLocalizations.po0PollIntervalTip(
                po0PollSecondsRange.min,
                po0PollSecondsRange.max,
              );
            }
            return null;
          },
          onChanged: (value) {
            final seconds = int.tryParse(value?.trim() ?? '');
            if (seconds != null) {
              _update(ref, (state) => state.copyWith(pollSeconds: seconds));
            }
          },
        ),
      ],
      footer: appLocalizations.po0AutoWhitelistDesc,
    );
  }
}

class _TokenSection extends ConsumerWidget {
  const _TokenSection();

  Future<void> _edit(BuildContext context, WidgetRef ref, {int? index}) async {
    final entries = ref.read(po0FirewallSettingProvider).tokenEntries;
    final current = index == null ? null : entries[index];
    final result = await dialogs.showCommonDialog<Po0TokenEntry>(
      child: _TokenDialog(
        entry: current,
        existing: {
          for (final (i, entry) in entries.indexed)
            if (i != index) entry.token,
        },
      ),
    );
    if (result == null || result == current) {
      return;
    }
    ref.read(po0FirewallSettingProvider.notifier).update((state) {
      final next = [...state.tokenEntries];
      if (index == null) {
        next.add(result);
      } else {
        next[index] = result;
      }
      return state.copyWith(tokenEntries: next);
    });
  }

  Future<void> _delete(BuildContext context, WidgetRef ref, int index) async {
    final appLocalizations = context.appLocalizations;
    final entry = ref.read(po0FirewallSettingProvider).tokenEntries[index];
    final confirmed = await dialogs.showMessage(
      title: appLocalizations.delete,
      destructive: true,
      message: TextSpan(text: appLocalizations.deleteTip(_displayName(entry))),
    );
    if (confirmed != true) {
      return;
    }
    ref.read(po0FirewallSettingProvider.notifier).update((state) {
      final next = [...state.tokenEntries]..removeAt(index);
      return state.copyWith(tokenEntries: next);
    });
  }

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final appLocalizations = context.appLocalizations;
    final entries = ref.watch(
      po0FirewallSettingProvider.select((state) => state.tokenEntries),
    );
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        ListHeader(
          title: appLocalizations.po0Tokens,
          actions: [
            IconButtonData(
              glyph: AppGlyphs.addCircle,
              tooltip: appLocalizations.po0AddToken,
              onPressed: () => unawaited(_edit(context, ref)),
            ),
          ],
        ),
        if (entries.isEmpty)
          Padding(
            padding: const EdgeInsets.symmetric(vertical: 32),
            child: NullStatus(
              label: appLocalizations.po0TokensEmpty,
              illustration: NullStatusIllustration.permission,
            ),
          )
        else
          generateSection(
            items: [
              for (final (index, entry) in entries.indexed)
                ListItem(
                  title: TooltipText(
                    text: Text(
                      _displayName(entry),
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                    ),
                  ),
                  subtitle: entry.name.isEmpty
                      ? null
                      : Text(Po0Token(entry.token).label),
                  trailing: IconButton(
                    tooltip: appLocalizations.delete,
                    icon: const GlyphIcon(AppGlyphs.delete),
                    onPressed: () => unawaited(_delete(context, ref, index)),
                  ),
                  onTap: () => unawaited(_edit(context, ref, index: index)),
                ),
            ],
          ),
        ListFooter(text: appLocalizations.po0TokensDesc),
      ],
    );
  }
}

String _displayName(Po0TokenEntry entry) =>
    entry.name.isNotEmpty ? entry.name : Po0Token(entry.token).label;

class _TokenDialog extends StatefulWidget {
  final Po0TokenEntry? entry;
  final Set<String> existing;

  const _TokenDialog({this.entry, required this.existing});

  @override
  State<_TokenDialog> createState() => _TokenDialogState();
}

class _TokenDialogState extends State<_TokenDialog> {
  final _formKey = GlobalKey<FormState>();
  late final _tokenController = TextEditingController(
    text: widget.entry?.token ?? '',
  );
  late final _nameController = TextEditingController(
    text: widget.entry?.name ?? '',
  );

  @override
  void dispose() {
    _tokenController.dispose();
    _nameController.dispose();
    super.dispose();
  }

  void _submit() {
    if (_formKey.currentState?.validate() != true) {
      return;
    }
    Navigator.of(context).pop(
      Po0TokenEntry(
        token: _tokenController.text.trim(),
        name: _nameController.text.trim(),
      ),
    );
  }

  String? _validateToken(String? value) {
    final appLocalizations = context.appLocalizations;
    final token = value?.trim() ?? '';
    if (token.isEmpty) {
      return appLocalizations.emptyTip('Token').trim();
    }
    if (!isPo0Token(token)) {
      return appLocalizations.po0TokenInvalid;
    }
    if (widget.existing.contains(token)) {
      return appLocalizations.existsTip('Token').trim();
    }
    return null;
  }

  @override
  Widget build(BuildContext context) {
    final appLocalizations = context.appLocalizations;
    return CommonDialog(
      title: widget.entry == null
          ? appLocalizations.po0AddToken
          : appLocalizations.po0EditToken,
      hasFields: true,
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(),
          child: Text(appLocalizations.cancel),
        ),
        TextButton(onPressed: _submit, child: Text(appLocalizations.confirm)),
      ],
      child: Form(
        key: _formKey,
        autovalidateMode: AutovalidateMode.onUserInteraction,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          spacing: 16,
          children: [
            SecretTextFormField(
              controller: _tokenController,
              autofocus: widget.entry == null,
              textInputAction: TextInputAction.next,
              decoration: const InputDecoration(hintText: 'pgnfw_…'),
              validator: _validateToken,
            ),
            TextFormField(
              controller: _nameController,
              maxLength: 32,
              decoration: InputDecoration(
                hintText: appLocalizations.po0TokenName,
              ),
              onFieldSubmitted: (_) => _submit(),
            ),
          ],
        ),
      ),
    );
  }
}

class _ResultSection extends ConsumerWidget {
  const _ResultSection();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final appLocalizations = context.appLocalizations;
    final setting = ref.watch(po0FirewallSettingProvider);
    final state = ref.watch(po0FirewallProvider);
    final lastRunAt = state.lastRunAt;
    if (!setting.enable || state.results.isEmpty || lastRunAt == null) {
      return const SizedBox.shrink();
    }
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        ListHeader(title: appLocalizations.po0Results),
        for (final result in state.results)
          Padding(
            padding: const EdgeInsets.only(bottom: 8),
            child: _ResultCard(result: result),
          ),
        ListFooter(text: appLocalizations.po0LastRun(lastRunAt.showTime)),
      ],
    );
  }
}

class _ResultCard extends StatelessWidget {
  final Po0TokenResult result;

  const _ResultCard({required this.result});

  (String, Color) _status(BuildContext context) {
    final appLocalizations = context.appLocalizations;
    final colorScheme = context.colorScheme;
    return switch (result.type) {
      Po0ResultType.applied => (
        appLocalizations.po0StatusApplied,
        colorScheme.success,
      ),
      Po0ResultType.notApplied => (
        appLocalizations.po0StatusNotApplied,
        colorScheme.warning,
      ),
      Po0ResultType.disabled => (
        appLocalizations.po0StatusDisabled,
        colorScheme.warning,
      ),
      Po0ResultType.rejected => (
        appLocalizations.po0StatusRejected,
        colorScheme.error,
      ),
      Po0ResultType.error => (
        appLocalizations.po0StatusError,
        colorScheme.error,
      ),
    };
  }

  @override
  Widget build(BuildContext context) {
    final appLocalizations = context.appLocalizations;
    final colorScheme = context.colorScheme;
    final (status, statusColor) = _status(context);
    final currentIp = result.currentIp;
    final limit = result.limit;
    final message = result.message;
    return CommonCard(
      inert: true,
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        spacing: 8,
        children: [
          Row(
            spacing: 8,
            children: [
              Expanded(
                child: Text(
                  result.name ?? result.label,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: AppTextStyle.headline.of(context),
                ),
              ),
              Text(
                status,
                style: AppTextStyle.subheadline
                    .of(context)
                    .copyWith(color: statusColor),
              ),
            ],
          ),
          if (currentIp != null)
            Text(
              appLocalizations.po0CurrentExit(currentIp),
              style: AppTextStyle.footnote
                  .of(context)
                  .copyWith(color: colorScheme.onSurfaceVariant),
            ),
          if (message != null)
            Text(
              message,
              style: AppTextStyle.footnote
                  .of(context)
                  .copyWith(color: colorScheme.onSurfaceVariant),
            ),
          if (result.whitelist.isNotEmpty) ...[
            Text(
              limit == null
                  ? appLocalizations.po0WhitelistEntries
                  : '${appLocalizations.po0WhitelistEntries} '
                        '${result.whitelist.length}/$limit',
              style: AppTextStyle.footnote
                  .of(context)
                  .copyWith(color: colorScheme.onSurfaceVariant),
            ),
            Wrap(
              spacing: 6,
              runSpacing: 6,
              children: [
                for (final entry in result.whitelist)
                  TonalChip(
                    label: entry.slot == null
                        ? entry.ip
                        : '${entry.ip} #${entry.slot}',
                    color: sameC24(entry.ip, currentIp)
                        ? colorScheme.successContainer
                        : context.raisedSurfaceLevel.colorOf(colorScheme),
                    foregroundColor: sameC24(entry.ip, currentIp)
                        ? colorScheme.onSuccessContainer
                        : colorScheme.onSurfaceVariant,
                  ),
              ],
            ),
          ],
        ],
      ),
    );
  }
}
